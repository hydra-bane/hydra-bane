// Spike 1: can koffi drive the handle-based Win32 calls the safety core needs?
// Checks: open without following reparse points, 128-bit FILE_ID_INFO, final path by handle,
// rename-by-handle (FileRenameInfoEx), Restart Manager lock owner lookup.
import koffi from 'koffi';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const k32 = koffi.load('kernel32.dll');
const rm = koffi.load('rstrtmgr.dll');

const CreateFileW = k32.func('void* __stdcall CreateFileW(str16 name, uint32 access, uint32 share, void* sa, uint32 disp, uint32 flags, void* tmpl)');
const CloseHandle = k32.func('bool __stdcall CloseHandle(void* h)');
const GetLastError = k32.func('uint32 __stdcall GetLastError()');
const GetFileInformationByHandleEx = k32.func('bool __stdcall GetFileInformationByHandleEx(void* h, int cls, _Out_ uint8_t* buf, uint32 size)');
const SetFileInformationByHandle = k32.func('bool __stdcall SetFileInformationByHandle(void* h, int cls, uint8_t* buf, uint32 size)');
const GetFinalPathNameByHandleW = k32.func('uint32 __stdcall GetFinalPathNameByHandleW(void* h, _Out_ uint16_t* buf, uint32 len, uint32 flags)');

const DELETE = 0x00010000, FILE_READ_ATTRIBUTES = 0x80, SYNCHRONIZE = 0x00100000;
const SHARE_ALL = 0x1 | 0x2 | 0x4, OPEN_EXISTING = 3;
const FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000, FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
const FileIdInfo = 18, FileRenameInfoEx = 22;
const FILE_RENAME_FLAG_POSIX_SEMANTICS = 0x2;
const INVALID = -1n;

const results = {};
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hb-spike-'));
const src = path.join(dir, 'victim.txt');
const dst = path.join(dir, 'quarantine', 'victim.txt');
fs.mkdirSync(path.dirname(dst));
fs.writeFileSync(src, 'x'.repeat(4096));

const open = (p) => {
  const h = CreateFileW(p, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, SHARE_ALL, null, OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, null);
  if (koffi.address(h) === BigInt.asUintN(64, INVALID)) throw new Error(`CreateFileW failed ${GetLastError()}`);
  return h;
};

// 1) FILE_ID_INFO
let h = open(src);
const idBuf = new Uint8Array(24);
results.fileIdInfo = GetFileInformationByHandleEx(h, FileIdInfo, idBuf, 24)
  ? { volumeSerial: Buffer.from(idBuf.slice(0, 8)).readBigUInt64LE().toString(16), fileId128: Buffer.from(idBuf.slice(8)).toString('hex') }
  : `FAIL ${GetLastError()}`;

// 2) final path by handle
const pbuf = new Uint16Array(1024);
const n = GetFinalPathNameByHandleW(h, pbuf, 1024, 0);
results.finalPath = n > 0 ? String.fromCharCode(...pbuf.slice(0, n)) : `FAIL ${GetLastError()}`;

// 3) rename by handle (object checked == object moved)
const target = '\\\\?\\' + dst;
const nameBytes = Buffer.from(target, 'utf16le');
const rbuf = Buffer.alloc(20 + nameBytes.length + 2);
rbuf.writeUInt32LE(FILE_RENAME_FLAG_POSIX_SEMANTICS, 0); // Flags
rbuf.writeBigUInt64LE(0n, 8);                            // RootDirectory = NULL
rbuf.writeUInt32LE(nameBytes.length, 16);                // FileNameLength (bytes)
nameBytes.copy(rbuf, 20);
const ok = SetFileInformationByHandle(h, FileRenameInfoEx, rbuf, rbuf.length);
results.renameByHandle = ok ? 'OK' : `FAIL ${GetLastError()}`;
CloseHandle(h);
results.movedExists = fs.existsSync(dst) && !fs.existsSync(src);
if (results.movedExists) {
  h = open(dst);
  const id2 = new Uint8Array(24);
  GetFileInformationByHandleEx(h, FileIdInfo, id2, 24);
  results.sameFileIdAfterMove = Buffer.from(id2.slice(8)).toString('hex') === results.fileIdInfo.fileId128;
  CloseHandle(h);
}

// 4) Restart Manager: who holds a file open?
const RM_PROCESS_INFO = koffi.struct('RM_PROCESS_INFO', {
  pid: 'uint32', startLow: 'uint32', startHigh: 'uint32',
  appName: koffi.array('uint16', 256), svcName: koffi.array('uint16', 64),
  appType: 'int', appStatus: 'uint32', tsSessionId: 'uint32', restartable: 'bool',
});
const RmStartSession = rm.func('uint32 __stdcall RmStartSession(_Out_ uint32* h, uint32 flags, _Out_ uint16_t* key)');
const RmRegisterResources = rm.func('uint32 __stdcall RmRegisterResources(uint32 h, uint32 nFiles, str16* files, uint32 nApps, void* apps, uint32 nSvc, void* svcs)');
const RmGetList = rm.func('uint32 __stdcall RmGetList(uint32 h, _Out_ uint32* needed, _Inout_ uint32* count, _Out_ RM_PROCESS_INFO* info, _Out_ uint32* reasons)');
const RmEndSession = rm.func('uint32 __stdcall RmEndSession(uint32 h)');

const fd = fs.openSync(dst, 'r'); // hold a handle in this process
const sess = [0]; const key = new Uint16Array(33);
let rc = RmStartSession(sess, 0, key);
rc = rc || RmRegisterResources(sess[0], 1, [dst], 0, null, 0, null);
const needed = [0], count = [8], reasons = [0];
const infos = Array.from({ length: 8 }, () => ({}));
rc = rc || RmGetList(sess[0], needed, count, infos, reasons);
RmEndSession(sess[0]);
fs.closeSync(fd);
results.restartManager = rc === 0
  ? { holders: infos.slice(0, count[0]).map(i => ({ pid: i.pid, app: String.fromCharCode(...i.appName).replace(/\0.*$/, '') })), selfPid: process.pid }
  : `FAIL rc=${rc}`;

fs.rmSync(dir, { recursive: true, force: true });
console.log(JSON.stringify(results, null, 2));

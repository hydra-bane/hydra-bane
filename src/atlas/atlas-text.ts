import type { ExplainText } from '../core/explain.ts';
import type { Category } from '../core/scan.ts';

export const ATLAS_TEXT: Partial<Record<Category, ExplainText>> = {
  atlas: {
    what: 'An installed program listed in the Hydra-bane Atlas. Hydra-bane does not judge the program. It lists what the program does on this PC (trusted root certificates it installed, ports it listens on, services that start with Windows), measured just now, and what named third parties such as government CERTs published about the version you have, quoted with their date and link.',
    why: 'Every line is either a measurement on this PC or a quote with its source; advisories are marked as covering your version only when their version range includes it. You decide whether to keep the program. Hydra-bane never deletes it itself: removing it runs the vendor\'s own uninstaller, and only after checking it (Windows Installer with the product code, or an uninstaller signed with the vendor certificate recorded in the Atlas). When a check fails it only tells you how to remove the program in Settings.',
    after: 'The vendor\'s uninstall window opens and you finish there. Hydra-bane cannot undo this; a site (a bank, a government service) may ask you to reinstall it, and you can install it again from there. Leftover files are reported, not removed.',
  },
  app: {
    what: 'An installed program you asked to remove, found in the Windows list of installed programs (the Uninstall registry keys). Hydra-bane does not judge the program; it only checks whether its own uninstaller can be run safely.',
    why: 'The registry entry is treated as data, never as a command. Hydra-bane runs the uninstaller only when one check holds: it is a Windows Installer product (Hydra-bane builds "msiexec /x {product code}" itself), or the uninstaller carries a valid signature from the program\'s own publisher, or the program is installed for all users and only administrators can change the uninstaller file and its folder. Shells, script hosts and arguments that point outside the program\'s folder are refused. Everything is checked again right before it runs. If no check holds, it only tells you how to remove the program in Settings.',
    after: 'The program\'s own uninstall window opens (Windows may ask for administrator approval first) and you finish there. This cannot be undone; install the program again if you need it. Files and settings the uninstaller leaves behind can be found afterwards with: hydra-bane scan --only leftovers.',
  },
};

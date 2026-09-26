import type { ExplainText } from '../core/explain.ts';
import type { Category } from '../core/scan.ts';

export const ATLAS_TEXT: Partial<Record<Category, ExplainText>> = {
  atlas: {
    what: 'An installed program that the Hydra-bane Atlas lists as software you can remove yourself. The title shows the vendor, the Microsoft category terms it is listed under, and whether removal is recommended.',
    why: 'Every listing cites published third-party sources and carries the vendor\'s response when there is one. Hydra-bane never deletes the program itself: it runs only the vendor\'s own uninstaller, and only after checking it (Windows Installer with the product code, or an uninstaller signed with the vendor certificate recorded in the Atlas). When a check fails it only tells you how to remove the program in Settings.',
    after: 'The vendor\'s uninstall window opens and you finish there. Hydra-bane cannot undo this; reinstall from the vendor if you need the program again (some sites, such as banks, may ask you to). Leftover files are reported, not removed.',
  },
};

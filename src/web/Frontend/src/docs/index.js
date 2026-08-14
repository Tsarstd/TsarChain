import { DOC_CATEGORIES, ALL_DOCS, getDocById } from "./docNavigation";
import { ABOUT_DOCS } from "./aboutDocs";
import { GUIDE_DOCS } from "./guideDocs";
import { TSARCHAIN_DOCS } from "./tsarchainDocs";

export const getDocData = (docId) => {
  if (ABOUT_DOCS[docId]) {
    return {
      meta: getDocById(docId),
      type: "about",
      data: ABOUT_DOCS[docId]
    };
  }
  if (GUIDE_DOCS[docId]) {
    return {
      meta: getDocById(docId),
      type: "guide",
      data: GUIDE_DOCS[docId]
    };
  }
  if (TSARCHAIN_DOCS[docId]) {
    return {
      meta: getDocById(docId),
      type: "tsarchain",
      data: TSARCHAIN_DOCS[docId]
    };
  }
  return {
    meta: ALL_DOCS[0],
    type: "about",
    data: ABOUT_DOCS.grungepaper
  };
};

export {
  DOC_CATEGORIES,
  ALL_DOCS,
  getDocById,
  ABOUT_DOCS,
  GUIDE_DOCS,
  TSARCHAIN_DOCS
};

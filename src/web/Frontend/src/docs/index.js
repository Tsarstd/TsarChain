import { DOC_CATEGORIES, ALL_DOCS, getDocById } from "./docNavigation";

// About docs
import { grungepaperEn } from "./about/grungepaperEn";
import { grungepaperId } from "./about/grungepaperId";
import { graffitiprotocolEn } from "./about/graffitiprotocolEn";
import { graffitiprotocolId } from "./about/graffitiprotocolId";

// Guide docs
import { deployment } from "./guide/deployment";
import { installNative } from "./guide/installNative";
import { contributing } from "./guide/contributing";

// Tsarchain docs
import { architecture } from "./tsarchain/architecture";
import { apiAndRpc } from "./tsarchain/api_and_rpc";
import { performance } from "./tsarchain/perfomance";
import { references } from "./tsarchain/references";
import { tsarcoreNative } from "./tsarchain/tsarcoreNative";

export const ABOUT_DOCS = {
  grungepaper: {
    id: "grungepaper",
    category: "About",
    downloads: {
      en: grungepaperEn.download,
      id: grungepaperId.download
    },
    en: grungepaperEn,
    id_lang: grungepaperId
  },
  "graffiti-protocol": {
    id: "graffiti-protocol",
    category: "About",
    downloads: {
      en: graffitiprotocolEn.download,
      id: graffitiprotocolId.download
    },
    en: graffitiprotocolEn,
    id_lang: graffitiprotocolId
  }
};

export const GUIDE_DOCS = {
  deployment,
  "install-native": installNative,
  contributing
};

export const TSARCHAIN_DOCS = {
  architecture,
  api: apiAndRpc,
  performance,
  references,
  "tsarcore-native": tsarcoreNative
};

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
  getDocById
};

import { toast } from "./toast";

export const copyText = async (text, label = "Copied to clipboard!") => {
  if (!text) return false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const el = document.createElement("textarea");
      el.value = text;
      el.style.position = "fixed";
      el.style.left = "-9999px";
      el.style.top = "-9999px";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      el.remove();
    }
    toast(label, "success");
    return true;
  } catch (err) {
    console.error("Copy failed:", err);
    toast("Failed to copy", "error");
    return false;
  }
};

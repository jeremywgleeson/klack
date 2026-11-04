const RGB_CHANNEL = String.raw`[+-]?(?:\d+(?:\.\d*)?|\.\d+)%?`;
const RGB_CHANNEL_LIST = new RegExp(
  String.raw`^${RGB_CHANNEL}\s*,\s*${RGB_CHANNEL}\s*,\s*${RGB_CHANNEL}$`,
);

export function normalizeSlackColor(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  // Slack's stock theme exposes channels such as "29, 28, 29", while Klack
  // and custom themes commonly replace the same property with a full color.
  return RGB_CHANNEL_LIST.test(trimmed) ? `rgb(${trimmed})` : trimmed;
}

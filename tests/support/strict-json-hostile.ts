import { STRICT_JSON_MAX_NUMBER_CHARACTERS_V1 } from "../../src/contract/strict-json-v1.js";

/**
 * U1g: one analyzer output text made hostile to the one strict parser in three ways, each
 * with the reason the parser gives: a repeated key (S2h), a number no double holds (S2i) and
 * a number token beyond the resource bound (U1g). The members are added to the first object
 * of `text` (the text itself, or the first entry of a top-level array); each variant keeps it
 * otherwise valid, so only the strict parser can refuse it.
 */
export function strictJsonHostileTextsV1(
  text: string,
): readonly (readonly [label: string, hostile: string, reason: RegExp])[] {
  const open = text.indexOf("{");
  if (open < 0 || text.slice(0, open).replace(/[[\s]/gu, "") !== "")
    throw new Error("an analyzer output fixture must be a JSON object or an array of them");
  const lead = (member: string) => `${text.slice(0, open + 1)}${member},${text.slice(open + 1)}`;
  return [
    ["a repeated key", lead('"aihRepeated":1,"aihRepeated":2'), /duplicate JSON object key/],
    ["a number no double holds", lead('"aihNumber":9007199254740993'), /no double holds exactly/],
    [
      "a number token beyond the bound",
      lead(`"aihNumber":0.${"0".repeat(STRICT_JSON_MAX_NUMBER_CHARACTERS_V1)}`),
      /a number longer than 1100 characters/,
    ],
  ];
}

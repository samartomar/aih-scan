// Portable fixture replay: copied beside the installed consumer and executed
// unchanged in its realm without Node globals or built-ins.
const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
export const summaryFixtureInput = entry => {
  const input = JSON.parse(JSON.stringify(entry.input));
  input.assessmentsInput.assessments = input.assessmentsInput.assessments.map(({ document, ...candidate }) => ({ ...candidate, bytes: new TextEncoder().encode(JSON.stringify(sort(document))) }));
  return input;
};
export async function replayItemSummaries(api, fixtures) {
  const entries = [...fixtures.cases.filter(c => c.input), ...fixtures.variants];
  for (const entry of entries) {
    const result = await api.summariseItem(summaryFixtureInput(entry));
    if (result.status !== 'summarised' || JSON.stringify(sort(result.summary)) !== JSON.stringify(sort(entry.value))) throw new Error(`Item summary ${entry.name}: ${JSON.stringify(result)}`);
    if (entry.row === 1 && result.selection !== null) throw new Error('No-source selection must be null');
    if (entry.row !== 1 && result.selection.status !== 'selected') throw new Error('Full selection is missing');
  }
  return { rows: fixtures.cases.filter(c => c.input).map(c => c.row), variants: fixtures.variants.length };
}

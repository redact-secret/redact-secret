/** Conservative path-argument budget below Windows' 32,767 UTF-16 limit. */
export const CLI_ARGUMENT_BUDGET = 16_000;

function quotedUpperBound(argument) {
  // Twice the JS string length plus separators safely covers Windows quoting.
  return argument.length * 2 + 3;
}

/** Partition arguments into non-empty, ordered batches under `budget`. */
export function batchArguments(arguments_, budget = CLI_ARGUMENT_BUDGET) {
  if (!Number.isSafeInteger(budget) || budget <= 0) {
    throw new Error("CLI argument budget must be a positive safe integer");
  }

  const batches = [];
  let batch = [];
  let used = 0;
  for (const argument of arguments_) {
    const cost = quotedUpperBound(argument);
    if (cost > budget) {
      throw new Error(`one CLI qualification argument exceeds the ${budget}-character budget`);
    }
    if (batch.length > 0 && used + cost > budget) {
      batches.push(batch);
      batch = [];
      used = 0;
    }
    batch.push(argument);
    used += cost;
  }
  if (batch.length > 0) batches.push(batch);
  return batches;
}

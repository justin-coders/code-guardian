/**
 * Code Guardian — Scanner Detector Matching (Phase 8C)
 *
 * Detectors are driven by *rule tables*: plain data describing which repository
 * entries constitute a signal. Keeping detection declarative means every rule is
 * auditable, testable and deterministic — there is no scoring, no probability and
 * no hidden heuristic anywhere in the scanner.
 *
 * Rule shape (every field is optional; all specified fields must match):
 *
 *   basename           exact file/directory name (string or array)
 *   basenamePattern    name glob, `*` and `?` only, no path separators
 *   path               exact repository-relative POSIX path
 *   directoryPath      entry lives inside this relative directory (any depth)
 *   directoryName      entry *is* a directory with this name (string or array)
 *   extension          file extension, compared lower-case (string or array)
 *   caseInsensitive    compare names/paths without case (for human-authored
 *                      entry points such as `README.md` or `Dockerfile`)
 *
 * Table order is significant: the **first matching rule wins**, so tables are
 * written most-specific first. Detection never falls back to a fuzzy match: an
 * entry that matches no rule produces no signal.
 */

/**
 * Compile a single-segment glob into an anchored regular expression.
 *
 * `*` and `?` cannot cross a `/`; every other character is escaped, so a rule can
 * never inject regular-expression behaviour.
 *
 * @param {string} pattern
 * @returns {RegExp}
 */
export function nameGlobToRegExp(pattern) {
  let source = "^";
  for (const character of pattern) {
    if (character === "*") source += "[^/]*";
    else if (character === "?") source += "[^/]";
    else source += character.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`${source}$`);
}

function asArray(value) {
  if (value === undefined) return null;
  return Array.isArray(value) ? value : [value];
}

function equalsSpecified(expected, actual, caseInsensitive) {
  const target = caseInsensitive ? actual.toLowerCase() : actual;
  return expected.some((candidate) => {
    const wanted = caseInsensitive ? candidate.toLowerCase() : candidate;
    return wanted === target;
  });
}

function insideDirectory(entry, directoryPath, caseInsensitive) {
  const prefix = caseInsensitive ? `${directoryPath.toLowerCase()}/` : `${directoryPath}/`;
  const candidate = caseInsensitive ? entry.path.toLowerCase() : entry.path;
  return candidate.startsWith(prefix);
}

/**
 * Whether an entry satisfies a rule.
 *
 * @param {object} rule
 * @param {{ path: string, name: string, extension: string, isDirectory: boolean }} entry
 * @returns {boolean}
 */
export function ruleMatchesEntry(rule, entry) {
  const caseInsensitive = rule.caseInsensitive === true;

  const names = asArray(rule.basename);
  if (names && !equalsSpecified(names, entry.name, caseInsensitive)) return false;

  const patterns = asArray(rule.basenamePattern);
  if (patterns) {
    const matches = patterns.some((pattern) =>
      nameGlobToRegExp(caseInsensitive ? pattern.toLowerCase() : pattern).test(
        caseInsensitive ? entry.name.toLowerCase() : entry.name,
      ),
    );
    if (!matches) return false;
  }

  if (rule.path !== undefined) {
    if (!equalsSpecified([rule.path], entry.path, caseInsensitive)) return false;
  }

  if (rule.directoryPath !== undefined) {
    if (!insideDirectory(entry, rule.directoryPath, caseInsensitive)) return false;
  }

  const directoryNames = asArray(rule.directoryName);
  if (directoryNames) {
    if (!entry.isDirectory) return false;
    if (!equalsSpecified(directoryNames, entry.name, caseInsensitive)) return false;
  }

  const extensions = asArray(rule.extension);
  if (extensions) {
    if (entry.isDirectory) return false;
    const target = entry.extension.toLowerCase();
    if (!extensions.some((candidate) => candidate.toLowerCase() === target)) {
      return false;
    }
  }

  return true;
}

/**
 * Find the first rule that matches an entry.
 *
 * @param {object[]} rules Ordered rule table.
 * @param {object} entry
 * @returns {object|null} The matching rule, or `null`.
 */
export function findRule(rules, entry) {
  for (const rule of rules) {
    if (ruleMatchesEntry(rule, entry)) return rule;
  }
  return null;
}

/**
 * Pair every entry with its first matching rule, preserving entry order.
 *
 * @param {object[]} rules
 * @param {object[]} entries
 * @returns {Array<{ rule: object, entry: object }>}
 */
export function matchEntries(rules, entries) {
  const matches = [];
  for (const entry of entries) {
    const rule = findRule(rules, entry);
    if (rule) matches.push({ rule, entry });
  }
  return matches;
}

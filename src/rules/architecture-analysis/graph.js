/**
 * Code Guardian — Architecture Graph Algorithms (Official Roadmap Phase 14)
 *
 * Small, pure, deterministic graph helpers the rules and the summary share. Nothing here reads
 * a model, a file or a clock: it operates on the module graph the signals module already built,
 * so the cycle the cycle rule reports and the cycle the summary counts are computed by exactly
 * one implementation.
 */

/**
 * The strongly connected components of the module graph, deterministic and iterative.
 *
 * Iterative Tarjan, so a pathological graph cannot exhaust the call stack, and every adjacency
 * list is pre-sorted so the component order never depends on insertion order.
 *
 * @param {string[]} nodes Sorted module paths.
 * @param {Map<string, string[]>} adjacency Sorted neighbor lists.
 * @returns {string[][]} Components, each sorted, in discovery order.
 */
export function stronglyConnectedComponents(nodes, adjacency) {
  let index = 0;
  const indices = new Map();
  const low = new Map();
  const onStack = new Set();
  const stack = [];
  const components = [];

  for (const root of nodes) {
    if (indices.has(root)) continue;
    const work = [{ node: root, edgeIndex: 0 }];

    while (work.length > 0) {
      const frame = work[work.length - 1];
      const node = frame.node;

      if (frame.edgeIndex === 0) {
        indices.set(node, index);
        low.set(node, index);
        index += 1;
        stack.push(node);
        onStack.add(node);
      }

      const neighbors = adjacency.get(node) ?? [];
      let descended = false;
      while (frame.edgeIndex < neighbors.length) {
        const next = neighbors[frame.edgeIndex];
        frame.edgeIndex += 1;
        if (!indices.has(next)) {
          work.push({ node: next, edgeIndex: 0 });
          descended = true;
          break;
        }
        if (onStack.has(next)) {
          low.set(node, Math.min(low.get(node), indices.get(next)));
        }
      }
      if (descended) continue;

      if (low.get(node) === indices.get(node)) {
        const component = [];
        let member;
        do {
          member = stack.pop();
          onStack.delete(member);
          component.push(member);
        } while (member !== node);
        components.push(component.sort());
      }

      work.pop();
      if (work.length > 0) {
        const parent = work[work.length - 1].node;
        low.set(parent, Math.min(low.get(parent), low.get(node)));
      }
    }
  }

  return components;
}

/**
 * The cycles of the module graph: strongly connected components with two or more modules, in a
 * deterministic order with each component sorted.
 *
 * @param {object} graph A module graph from `buildModuleGraph`.
 * @returns {string[][]} Cycle member lists.
 */
export function findModuleCycles(graph) {
  const nodes = graph.modules.map((module) => module.path);
  const adjacency = new Map();
  for (const edge of graph.edges) {
    const list = adjacency.get(edge.from);
    if (list === undefined) adjacency.set(edge.from, [edge.to]);
    else list.push(edge.to);
  }
  for (const list of adjacency.values()) list.sort();

  return stronglyConnectedComponents(nodes, adjacency)
    .filter((component) => component.length >= 2)
    .sort((a, b) => (a.join("\u0000") < b.join("\u0000") ? -1 : 1));
}

/** Whether a repository-relative path names a module entry file (`index.<ext>`). */
export function isEntryFile(path) {
  const slash = path.lastIndexOf("/");
  const basename = slash === -1 ? path : path.slice(slash + 1);
  return /^index\.[A-Za-z0-9]+$/.test(basename);
}

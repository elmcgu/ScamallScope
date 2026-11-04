// Layout options, shared by the page and the layout test.
// fcose is built for nested (compound) graphs and packs separate VPCs side by side.
export const LAYOUT = {
  name: "fcose", quality: "proof", animate: false, fit: false, randomize: true,
  nodeDimensionsIncludeLabels: true, packComponents: true, uniformNodeDimensions: false,
  idealEdgeLength: 70, nodeRepulsion: 6500, nestingFactor: 0.1, gravity: 0.3,
  gravityCompound: 1.2, gravityRangeCompound: 1.2, numIter: 2500,
  tilingPaddingVertical: 20, tilingPaddingHorizontal: 20,
};

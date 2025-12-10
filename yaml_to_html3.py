#!/usr/bin/env python3

# python3 yaml_visualiser.py input.yaml output.html

import sys
import yaml
import json

# ---------------------------
# YAML → Tree conversion
# ---------------------------

def yaml_to_tree(value, name=None):
    node = {}

    if name is not None:
        node["name"] = str(name)

    if isinstance(value, dict):
        node.setdefault("name", "")
        node["children"] = [yaml_to_tree(v, k) for k, v in value.items()]
        return node

    if isinstance(value, list):
        node.setdefault("name", "")
        children = []

        for idx, item in enumerate(value):
            label = f"[{idx}]"

            if isinstance(item, dict) and item:
                first_key = next(iter(item))
                first_val = item[first_key]
                label += f" {first_key}={first_val}"

            children.append(yaml_to_tree(item, label))

        node["children"] = children
        return node

    node["name"] = f"{name}: {value}" if name else str(value)
    return node


def build_tree_from_yaml(yaml_data, filename):
    if isinstance(yaml_data, dict) and len(yaml_data) == 1:
        key = next(iter(yaml_data))
        return yaml_to_tree(yaml_data[key], key)

    return {
        "name": filename,
        "children": [yaml_to_tree(v, k) for k, v in yaml_data.items()]
    }

# ---------------------------
# HTML TEMPLATE
# ---------------------------

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<meta charset="utf-8">
<html>
<head>
<title>YAML Tree Viewer</title>
<script src="https://d3js.org/d3.v7.min.js"></script>

<style>
html, body {
  margin: 0;
  padding: 0;
  height: 100%;
  font-family: Arial, sans-serif;
  overflow: hidden;
}

#controls {
  padding: 8px;
  background: #f5f5f5;
  border-bottom: 1px solid #ccc;
}

#chart {
  width: 100vw;
  height: calc(100vh - 120px);
  overflow: auto;
  position: relative;
  background: #fafafa;
}

select, button, input {
  margin-top: 6px;
  margin-right: 6px;
  padding: 4px 8px;
}

.node rect {
  rx: 6;
  ry: 6;
  stroke: #333;
  stroke-width: 1px;
  cursor: move;
}

.node text {
  font-size: 11px;
  fill: white;
  pointer-events: none;
}

.node.match rect {
  fill: #ffeb3b !important;
  stroke: #d32f2f;
  stroke-width: 2px;
}

.node.match text {
  fill: #000;
  font-weight: bold;
}

.node.hidden {
  display: none;
}

.link {
  fill: none;
  stroke: #999;
  stroke-width: 1px;
}

.link.hidden {
  display: none;
}

#searchInfo {
  margin-left: 10px;
  font-size: 13px;
}
</style>
</head>

<body>

<div id="controls">
  Orientation:
  <select id="orientation">
    <option value="LR" selected>Left → Right</option>
    <option value="TB">Top → Bottom</option>
  </select>

  <button id="expandAll">Expand All</button>
  <button id="collapseAll">Collapse All</button>
  <button id="resetView">Reset View</button>

  <br/>

  🔎 Search:
  <input id="search" placeholder="text to find..." />
  <label>
    <input type="checkbox" id="filterMode" />
    Filter (show only related tree)
  </label>

  <span id="searchInfo">Search results: 0 matches</span>
</div>

<div id="chart"></div>

<script>
const data = DATA_JSON;
const colors = ["#4e79a7", "#59a14f", "#f28e2b", "#e15759", "#76b7b2"];
const PADDING = 12;

const CANVAS_WIDTH = 5000;
const CANVAS_HEIGHT = 5000;

let g, root, svg;
let currentOrientation = "LR";

const zoom = d3.zoom()
  .scaleExtent([0.3, 20])
  .on("zoom", e => g.attr("transform", e.transform));

function render(orientation) {
  currentOrientation = orientation;

  d3.select("#chart").selectAll("*").remove();

  svg = d3.select("#chart")
    .append("svg")
    .attr("width", CANVAS_WIDTH)
    .attr("height", CANVAS_HEIGHT)
    .call(zoom);

  g = svg.append("g");

  root = d3.hierarchy(data);

  const tree = d3.tree()
    .nodeSize(orientation === "TB" ? [160, 120] : [80, 300])
    .separation((a, b) => a.parent === b.parent ? 1.8 : 2.6);

  update();

  document.getElementById("resetView").onclick = resetView;
  document.getElementById("expandAll").onclick = () => { expand(root); update(); };
  document.getElementById("collapseAll").onclick = () => { root.children?.forEach(collapse); update(); };
  document.getElementById("search").oninput = runSearch;
  document.getElementById("filterMode").onchange = runSearch;

  function collapse(d) {
    if (d.children) { d._children = d.children; d.children = null; d._children.forEach(collapse); }
  }

  function expand(d) {
    if (d._children) { d.children = d._children; d._children = null; }
    if (d.children) d.children.forEach(expand);
  }

  function update() {
    tree(root);
    const nodes = root.descendants();

    nodes.forEach(d => {
      if (d.fx == null) { d.fx = orientation === "TB" ? d.x : d.y; d.fy = orientation === "TB" ? d.y : d.x; }
    });

    const node = g.selectAll(".node")
      .data(nodes, d => d.id || (d.id = Math.random()));

    const nodeEnter = node.enter()
      .append("g")
      .attr("class", "node")
      .call(d3.drag()
        .on("start", () => {})
        .on("drag", function(event, d) {
          d.fx += event.dx; d.fy += event.dy;
          d3.select(this).attr("transform", `translate(${d.fx},${d.fy})`);
          drawLinks();
        })
      )
      .on("click", (_, d) => {
        if(d.children){ d._children=d.children; d.children=null; } else { d.children=d._children; d._children=null; }
        update();
      });

    nodeEnter.append("text")
      .text(d => d.data.name)
      .attr("text-anchor", "middle")
      .attr("dy", "0.35em");

    nodeEnter.each(function(d) {
      const bbox = this.querySelector("text").getBBox();
      d.w = bbox.width + PADDING*2;
      d.h = bbox.height + PADDING;
    });

    nodeEnter.insert("rect","text")
      .attr("width", d=>d.w)
      .attr("height", d=>d.h)
      .attr("x", d=>-d.w/2)
      .attr("y", d=>-d.h/2)
      .attr("fill", d=>colors[d.depth % colors.length]);

    const merged = nodeEnter.merge(node);
    merged.attr("transform", d=>`translate(${d.fx},${d.fy})`);
    node.exit().remove();

    drawLinks();
    runSearch();
  }

  function drawLinks() {
    g.selectAll(".link")
      .data(root.links())
      .join("path")
      .attr("class","link")
      .attr("d", d=>{
        const sx=d.source.fx, sy=d.source.fy, tx=d.target.fx, ty=d.target.fy;
        return currentOrientation==="TB"
          ? `M${sx},${sy+d.source.h/2} C${sx},${(sy+ty)/2} ${tx},${(sy+ty)/2} ${tx},${ty-d.target.h/2}`
          : `M${sx+d.source.w/2},${sy} C${(sx+tx)/2},${sy} ${(sx+tx)/2},${ty} ${tx-d.target.w/2},${ty}`;
      });
  }

  function resetView() {
    if (!root) return;
    const rootNode = root;

    const containerWidth = document.getElementById("chart").clientWidth;
    const containerHeight = document.getElementById("chart").clientHeight;

    const rootX = rootNode.fx;
    const rootY = rootNode.fy;

    const currentTransform = d3.zoomTransform(svg.node());
    const centerX = containerWidth/2;
    const centerY = containerHeight/2;

    const dx = centerX - rootX * currentTransform.k;
    const dy = centerY - rootY * currentTransform.k;

    svg.transition().duration(500)
       .call(zoom.transform, d3.zoomIdentity.translate(dx, dy).scale(currentTransform.k));
  }
}

function runSearch() {
  const q=document.getElementById("search").value.trim().toLowerCase();
  const filterMode=document.getElementById("filterMode").checked;
  const nodes=g.selectAll(".node");
  const nodeData=nodes.data()||[];

  const matches=new Set(nodeData.filter(d=>q && d.data.name.toLowerCase().includes(q)));
  const ancestors=new Set();
  const descendants=new Set();

  matches.forEach(m=>{
    let p=m.parent;
    while(p){ ancestors.add(p); p=p.parent; }
    (function walk(n){ descendants.add(n); (n.children||[]).forEach(walk); (n._children||[]).forEach(walk); })(m);
  });

  nodes.classed("match", d=>matches.has(d))
       .classed("hidden", d=>q && filterMode && !(matches.has(d)||ancestors.has(d)||descendants.has(d)));

  g.selectAll(".link")
    .classed("hidden", d=>q && filterMode && (nodes.filter(n=>n===d.source).classed("hidden")||nodes.filter(n=>n===d.target).classed("hidden")));

  document.getElementById("searchInfo").textContent=
    `Search results: ${matches.size} match${matches.size!==1?'es':''}`;
}

render("LR");
document.getElementById("orientation").onchange=e=>render(e.target.value);
</script>

</body>
</html>
"""

# ---------------------------
# MAIN
# ---------------------------

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 yaml_visualiser.py input.yaml output.html")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = yaml.safe_load(f)

    tree = build_tree_from_yaml(data, sys.argv[1])
    html = HTML_TEMPLATE.replace("DATA_JSON", json.dumps(tree, ensure_ascii=False))

    with open(sys.argv[2], "w") as f:
        f.write(html)

    print(f"✅ Generated {sys.argv[2]}")

if __name__ == "__main__":
    main()

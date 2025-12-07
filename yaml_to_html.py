#!/usr/bin/env python3

#Command: python3 yaml_to_html.py <input-filename.yaml> <output-filename.html>

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
            if not isinstance(item, (dict, list)):
                children.append({"name": str(item)})
                continue

            label = None
            if isinstance(item, dict):
                for key in ("id", "name", "key"):
                    if key in item:
                        label = str(item[key])
                        break

            if label is None:
                label = f"[{idx}]"

            children.append(yaml_to_tree(item, label))

        node["children"] = children
        return node

    node["name"] = f"{name}: {value}" if name is not None else str(value)
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
  overflow: hidden;
  font-family: Arial, sans-serif;
}

#controls {
  padding: 8px;
  background: #f5f5f5;
  border-bottom: 1px solid #ccc;
}

#chart {
  width: 100vw;
  height: calc(100vh - 60px);
}

select, button {
  margin-top: 4px;
  margin-right: 6px;
  padding: 4px 8px;
}

.node rect {
  rx: 4;
  ry: 4;
  fill-opacity: 0.9;
  stroke: #333;
  stroke-width: 0.8px;
}

.node text {
  font-size: 10px;
  pointer-events: none;
  fill: white;
}

.link {
  fill: none;
  stroke: #999;
  stroke-width: 1px;
}
</style>
</head>

<body>

<div id="controls">
  Orientation:
  <select id="orientation">
    <option value="TB">Top → Bottom</option>
    <option value="LR">Left → Right</option>
  </select>
  <br/>
  <button id="expandAll">Expand All</button>
  <button id="collapseAll">Collapse All</button>
</div>

<div id="chart"></div>

<script>
const data = DATA_JSON;
const colors = ["#4e79a7", "#59a14f", "#f28e2b", "#e15759", "#76b7b2"];

const BOX_HEIGHT = 18;
const BOX_PADDING_X = 12;

// ✅ Zoom behavior (added)
const zoom = d3.zoom()
  .scaleExtent([0.2, 4])
  .on("zoom", (event) => {
    g.attr("transform", event.transform);
  });

let g;   // global reference for zoom

function render(orientation) {

  d3.select("#chart").selectAll("*").remove();

  const chart = d3.select("#chart");
  const width = chart.node().clientWidth;
  const height = chart.node().clientHeight;

  const svg = chart.append("svg")
    .attr("width", width)
    .attr("height", height)
    .call(zoom);   // ✅ attach zoom

  g = svg.append("g");

  const root = d3.hierarchy(data);

  const tree = d3.tree()
    .nodeSize(
      orientation === "TB"
        ? [140, 60]
        : [50, 220]
    );

  update(root);

  document.getElementById("expandAll").onclick = () => {
    expandAll(root);
    update(root);
  };

  document.getElementById("collapseAll").onclick = () => {
    root.children && root.children.forEach(collapse);
    update(root);
  };

  function collapse(d) {
    if (d.children) {
      d._children = d.children;
      d._children.forEach(collapse);
      d.children = null;
    }
  }

  function expandAll(d) {
    if (d._children) {
      d.children = d._children;
      d._children = null;
    }
    if (d.children) d.children.forEach(expandAll);
  }

  function update() {

    tree(root);

    const nodes = root.descendants();
    const links = root.links();

    const node = g.selectAll(".node")
      .data(nodes, d => d.id || (d.id = Math.random()));

    const nodeEnter = node.enter()
      .append("g")
      .attr("class", "node")
      .on("click", (e, d) => {
        if (d.children) {
          d._children = d.children;
          d.children = null;
        } else {
          d.children = d._children;
          d._children = null;
        }
        update();
      });

    nodeEnter.append("rect");
    nodeEnter.append("text")
      .attr("dy", "0.35em")
      .attr("text-anchor", "middle");

    nodeEnter.merge(node).each(function(d) {
      const text = d3.select(this).select("text").text(d.data.name);
      const bbox = text.node().getBBox();
      d.boxWidth = Math.min(bbox.width + BOX_PADDING_X, 200);

      d3.select(this).select("rect")
        .attr("width", d.boxWidth)
        .attr("height", BOX_HEIGHT)
        .attr("x", -d.boxWidth/2)
        .attr("y", -BOX_HEIGHT/2)
        .attr("fill", colors[d.depth % colors.length]);
    });

    nodeEnter.merge(node)
      .attr("transform", d =>
        orientation === "TB"
          ? `translate(${d.x},${d.y})`
          : `translate(${d.y},${d.x})`
      );

    node.exit().remove();

    g.selectAll(".link")
      .data(links)
      .join("path")
      .attr("class", "link")
      .attr("d", d => {
        let sx, sy, tx, ty;

        if (orientation === "TB") {
          sx = d.source.x;
          sy = d.source.y + BOX_HEIGHT / 2;
          tx = d.target.x;
          ty = d.target.y - BOX_HEIGHT / 2;
        } else {
          sx = d.source.y + d.source.boxWidth / 2;
          sy = d.source.x;
          tx = d.target.y - d.target.boxWidth / 2;
          ty = d.target.x;
        }

        const mid = orientation === "TB"
          ? (sy + ty) / 2
          : (sx + tx) / 2;

        return orientation === "TB"
          ? `M${sx},${sy} C${sx},${mid} ${tx},${mid} ${tx},${ty}`
          : `M${sx},${sy} C${mid},${sy} ${mid},${ty} ${tx},${ty}`;
      });

    const bounds = g.node().getBBox();
    svg
      .attr("viewBox", [
        bounds.x - 20,
        bounds.y - 20,
        bounds.width + 40,
        bounds.height + 40
      ])
      .call(
        zoom.transform,
        d3.zoomIdentity.translate(20 - bounds.x, 20 - bounds.y)
      ); // ✅ reset zoom to fit on render
  }
}

// initial render
render("TB");

// orientation switch
document.getElementById("orientation").onchange = e =>
  render(e.target.value);

window.addEventListener("resize", () => {
  render(document.getElementById("orientation").value);
});
</script>
</body>
</html>
"""


# ---------------------------
# MAIN
# ---------------------------

def main():
    if len(sys.argv) != 3:
        print("Usage: python yaml_tree_visualizer.py input.yaml output.html")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        yaml_data = yaml.safe_load(f)

    tree = build_tree_from_yaml(yaml_data, sys.argv[1])
    html = HTML_TEMPLATE.replace("DATA_JSON", json.dumps(tree, ensure_ascii=False))

    with open(sys.argv[2], "w") as f:
        f.write(html)

    print(f"Generated {sys.argv[2]}")

if __name__ == "__main__":
    main()

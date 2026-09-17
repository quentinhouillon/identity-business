use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use crate::models::Edge;


pub fn dfs(edges: &[Edge], current: &Uuid, visited: &mut HashSet<String>) {
    if !visited.insert(current.to_string()) {
        return;
    }

    for edge in edges {
        if &edge.source_id == current {
            dfs(edges, &edge.target_id, visited);
        }
    }
}

fn dfs_spof(
    edges: &[Edge],
    current: &Uuid,
    visited: &mut HashSet<String>,
    discovery_time: &mut HashMap<Uuid, usize>,
    low: &mut HashMap<Uuid, usize>,
    parent: &mut HashMap<Uuid, Option<Uuid>>,
    time: &mut usize,
    spofs: &mut HashSet<String>,
) {
    visited.insert(current.to_string());

    discovery_time.insert(*current, *time);
    low.insert(*current, *time);

    *time += 1;

    let mut children = 0;

    for edge in edges {
        let neighbor = if &edge.source_id == current {
            edge.target_id
        } else if &edge.target_id == current {
            edge.source_id
        } else {
            continue;
        };

        if parent.get(current) == Some(&Some(neighbor)) {
            continue;
        }

        if !visited.contains(&neighbor.to_string()) {
            children += 1;

            parent.insert(neighbor, Some(*current));

            dfs_spof(
                edges,
                &neighbor,
                visited,
                discovery_time,
                low,
                parent,
                time,
                spofs,
            );

            // low[current] = min(low[current], low[neighbor])
            let neighbor_low = low[&neighbor];

            if neighbor_low < low[current] {
                low.insert(*current, neighbor_low);
            }

            // SPOF Verification
            let is_root = parent[current].is_none();

            if is_root && children > 1 {
                spofs.insert(current.to_string());
            } else if !is_root && low[&neighbor] >= discovery_time[current] {
                spofs.insert(current.to_string());
            }
        } else {
            // Back edge
            let neighbor_discovery = discovery_time[&neighbor];

            if neighbor_discovery < low[current] {
                low.insert(*current, neighbor_discovery);
            }
        }
    }
}

pub fn spof(edges: &[Edge], nodes: &[Uuid]) -> HashSet<String> {
    let mut visited = HashSet::new();
    let mut discovery_time = HashMap::new();
    let mut low = HashMap::new();
    let mut parent: HashMap<Uuid, Option<Uuid>> = HashMap::new();

    let mut time = 0;
    let mut spofs = HashSet::new();

    for node in nodes {
        if !visited.contains(&node.to_string()) {
            parent.insert(*node, None);

            dfs_spof(
                edges,
                node,
                &mut visited,
                &mut discovery_time,
                &mut low,
                &mut parent,
                &mut time,
                &mut spofs,
            );
        }
    }

    spofs
}
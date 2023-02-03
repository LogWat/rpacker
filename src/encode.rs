/* huffman-encoding */
/* reference: https://zenn.dev/k_kuroguro/articles/f7a63cd08447b6 */

use bitvec::prelude::*;
use std::collections::{HashMap, BinaryHeap, HashSet};
use std::cmp::Reverse;

pub type Bits = BitVec<u8, Msb0>;
type Weight = u32;
type CharBitsMap = HashMap<u8, Bits>;

struct Code {
    compressed_char_count: u32,
    original_char_count: u32,
    tree_topology_size: u32,
    tree_topology: Bits,
    compressed_chars: Bits,
}
 
impl Code {
    fn to_bits(&self) -> Bits {
        fn to_u8_array(x: &u32) -> [u8; 4] {
            [
                ((x >> 24) & 0xff) as u8,
                ((x >> 16) & 0xff) as u8,
                ((x >> 8) & 0xff) as u8,
                (x & 0xff) as u8,
            ]
        }
    
        let mut result = Bits::new();
        result.extend(to_u8_array(&self.compressed_char_count));
        result.extend(to_u8_array(&self.original_char_count));
        result.extend(to_u8_array(&self.tree_topology_size));
        result.extend(self.tree_topology.clone());
        result.extend(self.compressed_chars.clone());
        result
    }
}
 
struct Tree {
    root: Box<Node>,
}
 
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Leaf {
    char: u8,
}
 
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Branch {
    right: Box<Node>,
    left: Box<Node>,
}
 
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Branch(Branch),
    Leaf(Leaf),
}
 
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct HeapData {
    weight: Reverse<Weight>,
    node: Box<Node>,
}
 
fn evaluate_weight(plane: &[u8]) -> BinaryHeap<HeapData> {
    let mut heap: BinaryHeap<HeapData> = BinaryHeap::new();
    let unique_chars: HashSet<&u8> = plane.iter().collect();
    for &char in unique_chars {
       heap.push(HeapData {
          weight: Reverse(plane.iter().filter(|x| **x == char).count() as Weight),
          node: Box::new(Node::Leaf(Leaf { char })),
       });
    }
    heap
}
 
fn generate_tree(heap: &mut BinaryHeap<HeapData>) -> Tree {
    loop {
        if heap.len() <= 1 {
            break;
        }
    
        let left = heap.pop().unwrap();
        let right = heap.pop().unwrap();
    
        let branch = Node::Branch(Branch {
            left: left.node,
            right: right.node,
        });
        heap.push(HeapData {
            weight: Reverse(left.weight.0.saturating_add(right.weight.0)),
            node: Box::new(branch),
        });
    }
 
    Tree {
       root: heap.pop().unwrap().node,
    }
}
 
fn generate_char_bits_map(tree: &Tree) -> CharBitsMap {
    fn search_by_dfs_nlr(node: Box<Node>, char_bits_map: &mut CharBitsMap, bits: &mut Bits) {
        match *node {
            Node::Branch(x) => {
                let mut left_bits = bits.clone();
                let mut right_bits = bits.clone();
    
                left_bits.push(false);
                right_bits.push(true);
    
                search_by_dfs_nlr(x.left, char_bits_map, &mut left_bits);
                search_by_dfs_nlr(x.right, char_bits_map, &mut right_bits);
            }
            Node::Leaf(x) => {
                if bits.len() == 0 {
                    bits.push(false);
                }
                char_bits_map.insert(x.char, bits.clone());
            }
        }
    }
 
    let mut char_bits_map: CharBitsMap = HashMap::new();
    let mut bits = Bits::new();
    search_by_dfs_nlr(tree.root.clone(), &mut char_bits_map, &mut bits);
    char_bits_map
}

 
fn encode_tree(tree: &Tree) -> Bits {
    fn search_by_dfs_lrn(node: Box<Node>, bits: &mut Bits) {
        match *node {
            Node::Branch(x) => {
                search_by_dfs_lrn(x.left, bits);
                search_by_dfs_lrn(x.right, bits);
                bits.push(false);
            }
            Node::Leaf(x) => {
                bits.push(true);
                bits.extend(&[x.char]);
            }
        }
    }
 
    let mut tree_topology = Bits::new();
    search_by_dfs_lrn(tree.root.clone(), &mut tree_topology);
    tree_topology.push(false);
    tree_topology
}

pub fn encode(plane: &[u8]) -> Bits {
    let mut heap = evaluate_weight(plane);
    let tree = generate_tree(&mut heap);
    let char_bits_map = generate_char_bits_map(&tree);
    let mut compressed_chars = Bits::new();
    for &char in plane {
        let bits = match char_bits_map.get(&char) {
            Some(x) => x,
            None => continue,
        };
        compressed_chars.extend(bits.iter());
    }

    let compressed_char_count = compressed_chars.len() as u32;
    let original_char_count = plane.len() as u32;
    let tree_topology = encode_tree(&tree);
    let tree_topology_size = tree_topology.len() as u32;

    Code {
        compressed_char_count,
        original_char_count,
        tree_topology_size,
        tree_topology,
        compressed_chars,
    }
    .to_bits()
}
use std::collections::BTreeMap;

use threshold_crypto::{
    PublicKeySet, PublicKeyShare, SecretKeySet, SecretKeyShare, Signature, SignatureShare,
};

type UserId = usize;
type NodeId = usize;
type Msg = String;

// The database schema that validator nodes use to store messages they receive from users.
// Messages are first indexed numerically by user ID then alphabetically by message. Each message
// is mapped to its list of validator signatures.
type MsgDatabase = BTreeMap<UserId, BTreeMap<Msg, Vec<NodeSignature>>>;

// An append-only list of chat message "blocks". Each block contains the user ID for the user who
// broadcast the message to the network, the message text, and the combined signature of the
// message. A block can be appended to this list each time our chat protocol runs its consensus
// algorithm.
type ChatLog = Vec<(UserId, Msg, Signature)>;

// Represents a network of nodes running a distributed chat protocol. Clients, or "users", of our
// network, create a string that they want to append to the network's `chat_log`, they broadcast
// this message to the network, and each node that receives the message signs it with their
// signing-key. When the network runs a round of consensus, each node contributes its set of signed
// messages. The first message to receive `threshold + 1` signatures from validator nodes
// gets added to the `chat_log`.
struct ChatNetwork {
    pk_set: PublicKeySet,
    nodes: Vec<Node>,
    chat_log: ChatLog,
    n_users: usize,
}

impl ChatNetwork {
    // Creates a new network of nodes running our distributed chat protocol.
    //
    // # Arguments
    //
    // `n_nodes` - the number of validator/signing nodes in the network.
    // `threshold` - a message must have `threshold + 1` validator signatures
    // before it can be added to the `chat_log`.
    fn new(n_nodes: usize, threshold: usize) -> Self {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        let nodes = (0..n_nodes)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id);
                let pk_share = pk_set.public_key_share(id);
                Node::new(id, sk_share, pk_share)
            })
            .collect();

        ChatNetwork {
            pk_set,
            nodes,
            chat_log: vec![],
            n_users: 0,
        }
    }

    fn create_user(&mut self) -> User {
        let user_id = self.n_users;
        let user = User::new(user_id);
        self.n_users += 1;
        user
    }

    fn get_node(&self, id: NodeId) -> &Node {
        self.nodes.get(id).expect("No `Node` exists with that ID")
    }

    fn get_mut_node(&mut self, id: NodeId) -> &mut Node {
        self.nodes
            .get_mut(id)
            .expect("No `Node` exists with that ID")
    }

    // Run a single round of the consensus algorithm. If consensus produced a new block, append
    // that block the chat log.
    fn step(&mut self) {
        if let Some(block) = self.run_consensus() {
            self.chat_log.push(block);
        }
    }

    // Our chat protocol's consensus algorithm. This algorithm produces a new block to append to the chat
    // log. Our consensus uses threshold-signing to verify a message has received enough
    // signature shares (i.e. has been signed by `threshold + 1` nodes).
    fn run_consensus(&self) -> Option<(UserId, Msg, Signature)> {
        // Create a new `MsgDatabase` of every message that has been signed by a validator node.
        let all_pending: MsgDatabase =
            self.nodes
                .iter()
                .fold(BTreeMap::new(), |mut all_pending, node| {
                    for (user_id, signed_msgs) in &node.pending {
                        let user_msgs = all_pending.entry(*user_id).or_insert_with(BTreeMap::new);
                        for (msg, sigs) in signed_msgs.iter() {
                            let sigs = sigs.iter().cloned();
                            user_msgs
                                .entry(msg.to_string())
                                .or_insert_with(Vec::new)
                                .extend(sigs);
                        }
                    }
                    all_pending
                });

        // Iterate over the `MsgDatabase` numerically by user ID, then iterate over each user's
        // messages alphabetically. Try to combine the validator signatures. The first message to
        // receive `threshold + 1` node signatures produces a valid "combined" signature
        // and is added to the chat log.
        for (user_id, signed_msgs) in &all_pending {
            for (msg, sigs) in signed_msgs.iter() {
                let sigs = sigs.iter().filter_map(|node_sig| {
                    let node_sig_is_valid = self
                        .get_node(node_sig.node_id)
                        .pk_share
                        .verify(&node_sig.sig, msg.as_bytes());

                    if node_sig_is_valid {
                        Some((node_sig.node_id, &node_sig.sig))
                    } else {
                        None
                    }
                });

                if let Ok(sig) = self.pk_set.combine_signatures(sigs) {
                    return Some((*user_id, msg.clone(), sig));
                }
            }
        }

        None
    }
}

// A network node running our chat protocol.
struct Node {
    id: NodeId,
    sk_share: SecretKeyShare,
    pk_share: PublicKeyShare,
    pending: MsgDatabase,
}

impl Node {
    fn new(id: NodeId, sk_share: SecretKeyShare, pk_share: PublicKeyShare) -> Self {
        Node {
            id,
            sk_share,
            pk_share,
            pending: BTreeMap::new(),
        }
    }

    // Receives a message from a user, signs the message with the node's signing-key share,
    // then adds the signed message to its database of `pending` messages.
    fn recv(&mut self, user_id: UserId, msg: Msg) {
        let sig = NodeSignature {
            node_id: self.id,
            sig: self.sk_share.sign(msg.as_bytes()),
        };
        self.pending
            .entry(user_id)
            .or_insert_with(BTreeMap::new)
            .entry(msg)
            .or_insert_with(Vec::new)
            .push(sig);
    }
}

#[derive(Clone, Debug)]
struct NodeSignature {
    node_id: NodeId,
    sig: SignatureShare,
}

// A client of our chat protocol.
struct User {
    id: UserId,
}

impl User {
    fn new(id: UserId) -> Self {
        User { id }
    }

    // Sends a message to one of the network's validator nodes.
    fn send(&self, node: &mut Node, msg: Msg) {
        node.recv(self.id, msg);
    }
}

fn main() {
    // Creates a new network of 3 nodes running our chat protocol. The protocol has a
    // signing-threshold of 1. This means each message requires 2 validator signatures before it can be
    // added to the chat log.
    let mut network = ChatNetwork::new(3, 1);
    let node1 = network.get_node(0).id;
    let node2 = network.get_node(1).id;

    // Register a new user, Alice, with the network. Alice wants to add a message to the chat log.
    let alice = network.create_user();
    let alice_greeting = "hey, this is alice".to_string();

    // Alice sends her message to a validator. The validator signs the message. Before Alice can
    // send her message to a second validator, the network runs a round of consensus. Because
    // Alice's message has only one validator signature, it is not added to the chat log.
    alice.send(network.get_mut_node(node1), alice_greeting.clone());
    network.step();
    assert!(network.chat_log.is_empty());

    // Alice sends her message to a second validator. The validator signs the message. Alice's
    // message now has two signatures (which is `threshold + 1` signatures). The network runs a
    // round of consensus, which successfully creates a combined-signature for Alice's message.
    // Alice's message is appended to the chat log.
    alice.send(network.get_mut_node(node2), alice_greeting);
    network.step();
    assert_eq!(network.chat_log.len(), 1);
}

import hashlib,sys
import pandas as pd
from datetime import datetime
import math
import collections
from sha3 import keccak_256


def hash_leaf(leaf_value):
    '''Convert a leaf value to a digest'''
    leaf_hash = keccak_256(leaf_value.encode('utf-8')).digest()
    return leaf_hash

def hash_node(left_hash, right_hash):
    '''Convert two digests to their Merkle node's digest'''
    return keccak_256(left_hash + right_hash).digest()

def make_tree(leafs):
    '''Compute the Merkle tree of a list of values.
    The result is returned as a list where each value represents one hash in the
    tree. The indices in the array are as in a binary heap array.
    '''
    num_leafs = len(leafs)
    depth = int(math.log2(num_leafs))
    assert(num_leafs == 2**depth)
    num_nodes = 2 * num_leafs
    tree = [None] * num_nodes
    i = 0
    for key, value in leafs.items():
        #iterate through dictionary of RRsets and join them as a single value
        val = [item if isinstance(item, str) else ''.join(item) for item in value]
        tree[2**depth + i] = hash_leaf(''.join(val))
        i = i + 1
    for j in range(2**depth - 1, 0, -1):
        tree[j] = hash_node(tree[2*j], tree[2*j + 1])
    return tree

def root(tree):
    return tree[1]

def sign(tree, indices):
    '''Given a Merkle tree and a set of indices, provide an authPath/signature consisting of nodes
    required to reconstruct the merkle root.'''
    depth = int(math.log2(len(tree))) - 1
    num_leafs = 2**depth
    num_nodes = 2*num_leafs
    known = [False] * num_nodes
    decommitment = []
    for i in indices:
        known[2**depth + i] = True
    for i in range(2**depth - 1, 0, -1):
        left = known[2*i]
        right = known[2*i + 1]
        if left and not right:
            decommitment += [tree[2*i + 1]]
        if not left and right:
            decommitment += [tree[2*i]]
        known[i] = left or right
    return decommitment

def verify(root, depth, dic_vals, decommitment, debug_print=True):
    '''Verify a set of leafs in the Merkle tree.
    
    Parameters
    ------------------------
    root
        Merkle root that is commited to.
    depth
        Depth of the Merkle tree. Equal to log2(number of leafs)
    dic_values
        Mapping leaf index => value of the values we want to decommit.
    decommitments
        List of intermediate values required for deconstruction.
    '''
    
    # Create a list of pairs [(tree_index, leaf_hash)] with tree_index decreasing
    queue = []
    for index, v in sorted(dic_vals.items(), reverse=True):
        tree_index = 2**depth + index
        val = [item if isinstance(item, str) else ''.join(item) for item in v]
        hash = hash_leaf(''.join(val))
        queue += [(tree_index, hash)]

    while True:
        assert(len(queue) >= 1)

        # Take the top from the queue
        (index, hash) = queue[0]
        queue = queue[1:]
        if debug_print:
            print(index, hash.hex())

        # The merkle root has tree index 1
        if index == 1:
            return hash == root
        
        # Even nodes get merged with a decommitment hash on the right
        elif index % 2 == 0:
            queue += [(index // 2, hash_node(hash, decommitment[0]))]
            decommitment = decommitment[1:]
        
        # Odd nodes can get merged with their neighbour
        elif len(queue) > 0 and queue[0][0] == index - 1:
                # Take the sibbling node from the stack
                (_, sibbling_hash) = queue[0]
                queue = queue[1:]

                # Merge the two nodes
                queue += [(index // 2, hash_node(sibbling_hash, hash))]
        
        # Remaining odd nodes are merged with a decommitment on the left
        else:
            # Merge with a decommitment hash on the left
            queue += [(index // 2, hash_node(decommitment[0], hash))]
            decommitment = decommitment[1:]

 ###############################Test####################################################

##read preprocessed data
df = pd.read_csv('../2021_all_ds_records.csv',skipinitialspace=True, usecols = ['TLD','RRset_DS'] )
leaves= df.set_index('TLD').T.to_dict('list')

#append random hash values to records to make leaf nodes power of 2
m = hashlib.sha256()  
S = 64  # number of characters in the string.
n = len(leaves)
if not math.log(n, 2).is_integer():
    p = int(math.log(n, 2)//1)
    for i in range(n, 2**(p+1)):
        str_index = str(i)
        ran = ''.join(random.choices(string.ascii_uppercase + string.digits, k = S))
        leaves[str_index] = [[str(ran)]]

#generate a tree out of the record leaves
startTime = datetime.now()
tree= make_tree(leaves)
fin_time = datetime.now() - startTime
print("tree generation time:", fin_time)
print(root(tree))

##sign all records by calculating authPath for each
startTime = datetime.now()
signatures = {}
for i in range(0, len(leaves)):
    dec = sign(tree,[i])
    #signatures[i] = dec -- store the signatures
fin_time = datetime.now() - startTime  
print('zone_signing', fin_time)

##sign a single record with an index 1
startTime = datetime.now()
authPath=sign(tree,[1])
fin_time = datetime.now() - startTime
print('t_signature', fin_time)

#verify the record with the authPath calculated before
startTime_ver = datetime.now()
val = {1:leaves['.pl']}
print(verify(root(tree),11,val,authPath))
finTime_ver = datetime.now() - startTime_ver
print('Verification time: ', finTime_ver)

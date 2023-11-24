
## std::collections::smt
| Procedure | Description |
| ----------- | ------------- |
| get | Returns the value stored under the specified key in a Sparse Merkle Tree with the specified root.<br /><br />If the value for a given key has not been set, the returned `V` will consist of all zeroes.<br /><br />Input:  [K, R, ...]<br /><br />Output: [V, R, ...]<br /><br />Depth 16: 91 cycles<br /><br />Depth 32: 87 cycles<br /><br />Depth 48: 94 cycles<br /><br />Depth 64: unimplemented |
| insert | Inserts the specified value into a Sparse Merkle Tree with the specified root under the<br /><br />specified key.<br /><br />The value previously stored in the SMT under this key is left on the stack together with<br /><br />the updated tree root.<br /><br />This assumes that the value is not [ZERO; 4]. If it is, the procedure fails.<br /><br />Input:  [V, K, R, ...]<br /><br />Output: [V_old, R_new, ...]<br /><br />Cycles:<br /><br />- Update existing leaf:<br /><br />- Depth 16: 137<br /><br />- Depth 32: 134<br /><br />- Depth 48: 139<br /><br />- Insert new leaf:<br /><br />- Depth 16: 102<br /><br />- Depth 32: 183<br /><br />- Depth 48: 183<br /><br />- Replace a leaf with a subtree:<br /><br />- Depth 16 -> 32: 242<br /><br />- Depth 16 -> 48: 265<br /><br />- Depth 32 -> 48: 255 |
| set | Sets the value associated with key K to V in a Sparse Merkle tree with root R. Returns the new<br /><br />root of the tree together with the value previously associated with key K.<br /><br />If no value was previously associated with K, [ZERO; 4] is returned.<br /><br />Unlike the `insert` procedure defined above, this procedure allows for values to be set to<br /><br />[ZERO; 4].<br /><br />Input:  [V, K, R, ...]<br /><br />Output: [V_old, R_new, ...]<br /><br />Cycles:<br /><br />- Update existing leaf:<br /><br />- Depth 16: 137<br /><br />- Depth 32: 133<br /><br />- Depth 48: 139<br /><br />- Insert new leaf:<br /><br />- Depth 16: 102<br /><br />- Depth 32: 183<br /><br />- Depth 48: 183<br /><br />- Replace a leaf with a subtree:<br /><br />- Depth 16 -> 32: 242<br /><br />- Depth 16 -> 48: 265<br /><br />- Depth 32 -> 48: 255<br /><br />- Remove a key-value pair:<br /><br />- Key-value pair not in tree: 52 - 93<br /><br />- Key-value pair is in tree: 142 - 305 |
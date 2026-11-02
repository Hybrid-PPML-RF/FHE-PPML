# Cost of the private-model changes on the MPC side (one tree level, L nodes in parallel, K candidate splits per node).
#
#   mode 0: BestSplit as now: argmax with an index payload (ml.argmax), vectorized over the L nodes
#   mode 1: ml.argmax_onehot (Compiler/ml.py): keeps the comparison bit of every merge and expands the bits top-down into the one-hot <e*>
#           (one multiplication per merge; the root's weight is the public 1)
#   mode 2: argmax that carries the one-hot as payload through the tournament (bottom-up; entries outside both subtrees
#           stay public zeros, so a merge costs one multiplication per candidate of the two subtrees)
#   mode 3: the selection <sel> = <X'> <E>: (n x K) shares of the candidate blocks times the (K x L) one-hots, n*L inner products
#
# usage:  ./compile.py bench_onehot K L n mode      (the compiler prints the triples / bits / rounds of the program)
# The inputs come from party 0, so they cost no triples or bits; only the computation is counted.

from Compiler import types, library, ml
from Compiler.util import tree_reduce

program.set_security(40)
program.set_bit_length(32)

K = int(program.args[1])
L = int(program.args[2])
n = int(program.args[3])
mode = int(program.args[4])

print_ln("bench_onehot K=%s L=%s n=%s mode=%s", K, L, n, mode)


class TNode:
    def __init__(self, val, leaf=None, left=None, right=None, bit=None, onehot=None):
        self.val, self.leaf, self.left, self.right, self.bit, self.onehot = val, leaf, left, right, bit, onehot


if mode in (0, 1, 2):
    # Gini values of candidate k for the L nodes of the level
    vals = [sint.get_input_from(0, size=L) for _ in range(K)]

if mode == 0:
    def op(a, b):
        c = b[1] < a[1]
        return c.if_else(a[0], b[0]), c.if_else(a[1], b[1])
    idx, best = tree_reduce(op, [(cint(k, size=L), v) for k, v in enumerate(vals)])
    print_ln("index of node 0: %s", idx[0].reveal())

elif mode == 1:
    e = ml.argmax_onehot(vals)                              # Compiler/ml.py: keeps the comparison bits, expands them top-down
    print_ln("e*[0] of node 0: %s", e[0][0].reveal())

elif mode == 2:
    zero = cint(0, size=L)
    one = cint(1, size=L)

    def merge(a, b):
        c = b.val < a.val
        oh = [c.if_else(x, y) for x, y in zip(a.onehot, b.onehot)]
        return TNode(c.if_else(a.val, b.val), bit=c, onehot=oh)
    leaves = [TNode(v, onehot=[one if j == k else zero for j in range(K)]) for k, v in enumerate(vals)]
    root = tree_reduce(merge, leaves)
    print_ln("e*[0] of node 0: %s", root.onehot[0][0].reveal())

elif mode == 3:
    X = sint.Matrix(n, K)
    X.input_from(0)
    E = sint.Matrix(K, L)
    E.input_from(0)
    S = X.dot(E)                                            # n x L: column l is <sel> of node l
    print_ln("sel[0] of node 0: %s", S[0][0].reveal())

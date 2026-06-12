
#x = 25200  # iris, 
#x = 12600 # iris with subset of attributes
#x = 119119 # wine
#x = 36652 # wine with subset of attributes
#x = 1026000 # cancer
#x = 205200 # cancer with subset of attributes

# number of labels, needed for the computation of gini
# t = 2
# t = 3
# t = 7
# t = 10
import itertools
import random
import math
#import numpy as np
from Compiler import types, library, instructions
from Compiler import comparison, util, ml
from Compiler.util import is_zero, tree_reduce
from Compiler import SC_fun

program.set_security(40)

# set the bit length of the cleartext for the comparisons
program.set_bit_length(16)

# Set the bit length based on edabit
bit_length = program.bit_length
print_ln("%s-bit_length", bit_length)
#default parameters for the benchmarks, which can be overwritten at compile time by passing arguments to the compiler
n = 100 # number of samples
m = 9   # number of attributes, needed for the computation of the number of possible split points
alpha = 4 # number of possible attribute values, needed for the computation of the number of possible split points
t = 3   # number of labels
d = 4   # depth of the tree
x = 12600 # number of multiplications needed for the computation of the GINI index terms for each node, with the G' formula of overleaf. This is needed to set the number of iterations for the benchmark, which should be representative of the actual number of multiplications needed for the computation of the GINI index in a real training scenario. The number of multiplications needed depends on the number of samples, attributes, attribute values, labels, and depth of the tree, as well as on the formula used for the computation of the GINI index. For example, for the wine dataset, x = 119119; for the cancer dataset, x = 1026000; etc..
bining = 1
# argmax to be computed collaboratively between the servers
# in parallel, on each tree level 
# e.g. if we assume 10 servers, each one training 10 decision trees\
    # then, on the first level d1 = 100 argmaxes can be computed independently, 
    # and on the second level d2=200 argmaxes in parallel, etc.. 
d1 = 100
d2 = 200 
d3 = 400
d4 = 800
d5 = 0
d6 = 0
h = 800
n_threads = 48

# n = 8 * \ceil[\sqrt(m)] 

try:
    n = int(program.args[1])
except:
    pass

try:
    m = int(program.args[2])
except:
    pass

try:
    alpha = int(program.args[3])
except:
    pass

try:
    t = int(program.args[4])
except:
    pass

try:
    d = int(program.args[5])
except:
    pass

try:
    bining = int(program.args[6])
except:
    pass

print_ln("Compiled with n=%s, m=%s, alpha=%s, t=%s, d=%s", n, m, alpha, t, d)

if (bining == 1):
    ma = 8 * math.ceil(math.sqrt(m))
if (bining == 0):    
    ma = alpha * math.ceil(math.sqrt(m)) # number of elements in each vector, which captures the different combinations of attributes and attribute values considered for possible split points. This is needed for the computation of the gini index, as well as for the argmax.

if (d==5):
    d5 = 1600
    h = 1600
if (d==6):
    d5 = 1600
    d6 = 3100
    h = 3100

x = ma*t*n # number of multiplications needed for the computation of the GINI index terms for each node, with the G' formula of overleaf. This is needed to set the number of iterations for the benchmark, which should be representative of the actual number of multiplications needed for the computation of the GINI index in a real training scenario. The number of multiplications needed depends on the number of samples, attributes, attribute values, labels, and depth of the tree, as well as on the formula used for the computation of the GINI index. For example, for the wine dataset, x = 119119; for the cancer dataset, x = 1026000; etc..

def compute_gini(a,b,c,d):
    #c1 = sint(0)
    #d1 = sint(0)
    #gini = a^2 + b^2 - \sum_{over t} c^2 vals - \sum_{over t} d^2 vals
    @for_range_opt(t)
    def _(j):
        c.square()
        d.square()    
    gini = (a.square() + b.square() - c - d)
    return gini


def create_val():
    val = types.sint.get_random_int(120, size=1)
    return  MemValue(val)

def create_a_values(n):
    a = types.sint.get_random_int(32,size=n)
    a = a.square()
    return a

def bench_mul(a,b):
    a*b


def bench_argmax(a_values):
    a_max = ml.argmax(a_values)  
    return a_max.reveal()    

def bench_max(a_values):
    a_max = ml.argmax(a_values)  
    idx = a_max.reveal()   
    return a_values[idx].reveal()


a_array = sint.Array(ma)
a_values = create_a_values(ma)  
a_array.assign(a_values)

t_array = sint.Array(t)
t_values = create_a_values(t)  
t_array.assign(t_values)

# benchmark the argmax 
start_timer(1)

@for_range_opt_multithread(n_threads, d1)
def _(i):
    #@for_range(l)
    #def _(i):
    a_max = ml.argmax(a_array)
@for_range_opt_multithread(n_threads, d2)
def _(i):
    #@for_range(l)
    #def _(i):
    a_max = bench_argmax(a_array)
@for_range_opt_multithread(n_threads, d3)
def _(i):
    #@for_range(l)
    #def _(i):
    a_max = bench_argmax(a_array)
@for_range_opt_multithread(n_threads, d4)
def _(i):
    #@for_range(l)
    #def _(i):
    if (d5==0):
        a_max = bench_argmax(t_array)
    if (d5!=0):
        a_max = bench_argmax(a_array)      
@for_range_opt_multithread(n_threads, d5)
def _(i):
    #@for_range(l)
    #def _(i):
    if (d6==0):
        a_max = bench_argmax(t_array)
    if (d6!=0):
        a_max = bench_argmax(a_array)
@for_range_opt_multithread(n_threads, d6)
def _(i):
    #@for_range(l)
    #def _(i):
    a_max = bench_argmax(t_array)               
stop_timer(1)

# benchmark computation of GINI index with G' formula of overleaf
#(without FHE, TOTAL IN MPC, n as below) 
aval = create_val()
bval = create_val()
cval = create_val()
dval = create_val()
start_timer(2)
@for_range_opt_multithread(n_threads, d1*x)
def _(i):
    bench_mul(aval,bval)    #term1
    bench_mul(aval,cval)    #term2
    bench_mul(aval,dval)    #term3
    bench_mul(bval,cval)    #term4        
    compute_gini(aval,bval,cval,dval)     
@for_range_opt_multithread(n_threads, d2*x)
def _(i):
    bench_mul(aval,bval)    #term1
    bench_mul(aval,cval)    #term2
    bench_mul(aval,dval)    #term3
    bench_mul(bval,cval)    #term4      
    compute_gini(aval,bval,cval,dval)
@for_range_opt_multithread(n_threads, d3*x)
def _(i):
    bench_mul(aval,bval)    #term1
    bench_mul(aval,cval)    #term2
    bench_mul(aval,dval)    #term3
    bench_mul(bval,cval)    #term4      
    compute_gini(aval,bval,cval,dval)   
@for_range_opt_multithread(n_threads, d4*x)
def _(i):
    bench_mul(aval,bval)    #term1
    bench_mul(aval,cval)    #term2
    bench_mul(aval,dval)    #term3
    bench_mul(bval,cval)    #term4      
    compute_gini(aval,bval,cval,dval)
@for_range_opt_multithread(n_threads, d5*x)
def _(i):
    bench_mul(aval,bval)    #term1
    bench_mul(aval,cval)    #term2
    bench_mul(aval,dval)    #term3
    bench_mul(bval,cval)    #term4      
    compute_gini(aval,bval,cval,dval)
@for_range_opt_multithread(n_threads, d6*x)
def _(i):
    bench_mul(aval,bval)    #term1
    bench_mul(aval,cval)    #term2
    bench_mul(aval,dval)    #term3
    bench_mul(bval,cval)    #term4      
    compute_gini(aval,bval,cval,dval)        
stop_timer(2)



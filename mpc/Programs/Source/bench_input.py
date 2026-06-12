# benchmark input sharing
# S = 2*(T*alpha*n*m) + 4*T*(2^d-1)*alpha*floor(sqrt(m))*t*n
#       + T*(2^d-1)*n*t + T*(2^d-1)*alpha*floor(sqrt(m))*t
T = 100  # number of parties*number of trees trained in parallel, which determines the number of inputs shared in parallel, and thus the number of iterations for the benchmark of input sharing. This is needed to set the number of iterations for the benchmark, which should be representative of the actual number of inputs shared in a real training scenario. The number of inputs shared depends on the number of parties, trees trained in parallel, samples, attributes, attribute values, labels, and depth of the tree. For example, for 10 parties training 10 trees in parallel, T=100; for 3 parties training 5 trees in parallel, T=15; etc..
sqm = math.floor(math.sqrt(m))
S1 = 2 * T * alpha * n * m
S2 = 4 * T * (2**d - 1) * alpha * sqm * t * n
S3 = T * (2**d - 1) * n * t
S4 = T * (2**d - 1) * alpha * sqm * t
S  = S1 + S2 + S3 + S4

print_ln("Sharing benchmark: S1=%s, S2=%s, S3=%s, S4=%s, S_total=%s",
         S1, S2, S3, S4, S)
array_a = types.personal(0, Array(S, types.cfix))
@for_range_opt(S)
def _(i):
    value = cint(42)
    value_cfix =  types.cfix(value)
    array_a[i] = value_cfix
start_timer(5)
array_sa = sfix.Array(S)
array_sa[:] = sfix(array_a[:])
stop_timer(5)

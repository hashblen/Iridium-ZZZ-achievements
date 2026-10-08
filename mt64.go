package main

type MT19937_64_3 struct {
	mt  [312]uint64
	mti uint32
}

func MT19937_64_new() *MT19937_64_3 {
	return &MT19937_64_3{
		mt:  [312]uint64{},
		mti: 0x139,
	}
}

func (r *MT19937_64_3) Seed(seed uint64) {
	r.mt[0] = seed
	for i := 1; i < 312; i++ {
		value := r.mt[i-1] ^ (r.mt[i-1] >> 62)
		r.mt[i] = (6364136223846793005*value + uint64(i)) & 0xffffffffffffffff
	}
	r.mti = 312
}

func (r *MT19937_64_3) NextULong() uint64 {
	if r.mti >= 312 {
		if r.mti == 313 {
			r.Seed(5489)
		}
		for k := 0; k < 311; k++ {
			y := (r.mt[k] & 0xffffffff80000000) | (r.mt[k+1] & 0x7fffffff)
			if k < (312 - 156) {
				val := func() uint64 {
					if y&1 == 0 {
						return 0
					} else {
						return 0xb5026f5aa96619e9
					}
				}()
				r.mt[k] = r.mt[k+156] ^ (y >> 1) ^ (val)
			} else {
				val := func() uint64 {
					if y&1 == 0 {
						return 0
					} else {
						return 0xb5026f5aa96619e9
					}
				}()
				r.mt[k] = r.mt[(k+156+312-624)%312] ^ (y >> 1) ^ (val)
			}
		}
		yy := (r.mt[311] & 0xffffffff80000000) | (r.mt[0] & 0x7fffffff)
		val2 := func() uint64 {
			if yy&1 == 0 {
				return 0
			} else {
				return 0xb5026f5aa96619e9
			}
		}()
		r.mt[311] = r.mt[155] ^ (yy >> 1) ^ (val2)
		r.mti = 0
	}
	x := r.mt[r.mti]
	r.mti += 1
	x ^= (x >> 29) & 0x5555555555555555
	x ^= (x << 17) & 0x71d67fffeda60000
	x ^= (x << 37) & 0xfff7eee000000000
	x ^= x >> 43
	return x
}

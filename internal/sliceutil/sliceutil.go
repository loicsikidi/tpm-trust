package sliceutil

func Filter[T any, S comparable](ts []T, fn func(T) (s S, include bool)) []S {
	ss := make([]S, 0, len(ts))
	seen := make(map[S]struct{}, len(ts))
	for _, t := range ts {
		if s, include := fn(t); include {
			if _, found := seen[s]; !found {
				seen[s] = struct{}{}
				ss = append(ss, s)
			}
		}
	}

	return ss
}

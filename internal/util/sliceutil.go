package util

// Filter applies a filter function to a slice and returns unique results.
// The filter function fn returns both the transformed value and a boolean indicating if it should be included.
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

// Map applies a transformation function to each element of a slice and returns a new slice with the results.
func Map[T any, U any](ts []T, fn func(T) U) []U {
	us := make([]U, len(ts))
	for i, t := range ts {
		us[i] = fn(t)
	}
	return us
}

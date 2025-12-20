package sliceutil

import (
	"reflect"
	"testing"
)

func TestFilter(t *testing.T) {
	t.Run("filter and deduplicate integers", func(t *testing.T) {
		input := []int{1, 2, 3, 2, 4, 3, 5}
		fn := func(i int) (int, bool) {
			return i, i > 2
		}

		got := Filter(input, fn)
		want := []int{3, 4, 5}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("filter with transformation", func(t *testing.T) {
		input := []string{"apple", "banana", "apricot", "cherry", "avocado"}
		fn := func(s string) (rune, bool) {
			firstChar := rune(s[0])
			return firstChar, firstChar == 'a'
		}

		got := Filter(input, fn)
		want := []rune{'a'}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("empty input slice", func(t *testing.T) {
		input := []int{}
		fn := func(i int) (int, bool) {
			return i, true
		}

		got := Filter(input, fn)
		want := []int{}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("no elements match filter", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(i int) (int, bool) {
			return i, i > 10
		}

		got := Filter(input, fn)
		want := []int{}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("all elements match and are unique", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(i int) (int, bool) {
			return i, true
		}

		got := Filter(input, fn)
		want := []int{1, 2, 3, 4, 5}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("all elements duplicate to same value", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		fn := func(i int) (int, bool) {
			return 42, true
		}

		got := Filter(input, fn)
		want := []int{42}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("complex type transformation", func(t *testing.T) {
		type Person struct {
			Name string
			Age  int
		}

		input := []Person{
			{"Alice", 30},
			{"Bob", 25},
			{"Charlie", 30},
			{"Diana", 35},
		}

		fn := func(p Person) (int, bool) {
			return p.Age, p.Age >= 30
		}

		got := Filter(input, fn)
		want := []int{30, 35}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})

	t.Run("string deduplication", func(t *testing.T) {
		input := []string{"hello", "world", "hello", "go", "world", "test"}
		fn := func(s string) (string, bool) {
			return s, len(s) > 3
		}

		got := Filter(input, fn)
		want := []string{"hello", "world", "test"}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Filter() = %v, want %v", got, want)
		}
	})
}

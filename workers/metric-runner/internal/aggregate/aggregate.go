package aggregate

import "math"

type Sample struct{ Numerator, Denominator float64 }
type Result struct {
	Numerator, Denominator, Value float64
	Status                        string
}

func Ratio(samples []Sample) Result {
	var n, d float64
	for _, s := range samples {
		if math.IsNaN(s.Numerator) || math.IsNaN(s.Denominator) || s.Denominator < 0 {
			return Result{Status: "UNKNOWN"}
		}
		n += s.Numerator
		d += s.Denominator
	}
	if d == 0 {
		return Result{Status: "UNKNOWN"}
	}
	return Result{Numerator: n, Denominator: d, Value: n / d, Status: "OK"}
}

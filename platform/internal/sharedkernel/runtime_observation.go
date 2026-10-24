package sharedkernel

// MaxToolObservationOutputBytes is the common producer/metadata-reader bound.
// Metadata reports only the byte count; it does not disclose this payload.
const MaxToolObservationOutputBytes = 1 << 20

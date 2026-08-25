package events

// Category groups events by the subsystem that produces them. Categories map
// one-to-one onto the reserved event-ID ranges documented in the event catalog.
type Category string

// Event categories.
const (
	CatConnectivity Category = "CONNECTIVITY" // 1000-1999
	CatPerformance  Category = "PERFORMANCE"  // 2000-2999
	CatAvailability Category = "AVAILABILITY" // 3000-3999
	CatTraffic      Category = "TRAFFIC"      // 4000-4999
	CatSecurity     Category = "SECURITY"     // 5000-5999
	CatNameRouting  Category = "DNS_ROUTING"  // 6000-6999
	CatInterface    Category = "INTERFACE"    // 7000-7999
	CatService      Category = "SERVICE"      // 8000-8999
	CatInternal     Category = "INTERNAL"     // 9000-9999
	CatUnknown      Category = "UNKNOWN"
)

// AllCategories lists every category in event-ID order.
func AllCategories() []Category {
	return []Category{
		CatConnectivity, CatPerformance, CatAvailability, CatTraffic, CatSecurity,
		CatNameRouting, CatInterface, CatService, CatInternal,
	}
}

// CategoryForCode derives the category from an event ID using the reserved ranges.
func CategoryForCode(code int) Category {
	switch {
	case code >= 1000 && code < 2000:
		return CatConnectivity
	case code >= 2000 && code < 3000:
		return CatPerformance
	case code >= 3000 && code < 4000:
		return CatAvailability
	case code >= 4000 && code < 5000:
		return CatTraffic
	case code >= 5000 && code < 6000:
		return CatSecurity
	case code >= 6000 && code < 7000:
		return CatNameRouting
	case code >= 7000 && code < 8000:
		return CatInterface
	case code >= 8000 && code < 9000:
		return CatService
	case code >= 9000 && code < 10000:
		return CatInternal
	}
	return CatUnknown
}

// CategoryRange returns the inclusive-exclusive ID range reserved for a category.
func CategoryRange(c Category) (lo, hi int) {
	switch c {
	case CatConnectivity:
		return 1000, 2000
	case CatPerformance:
		return 2000, 3000
	case CatAvailability:
		return 3000, 4000
	case CatTraffic:
		return 4000, 5000
	case CatSecurity:
		return 5000, 6000
	case CatNameRouting:
		return 6000, 7000
	case CatInterface:
		return 7000, 8000
	case CatService:
		return 8000, 9000
	case CatInternal:
		return 9000, 10000
	}
	return 0, 0
}

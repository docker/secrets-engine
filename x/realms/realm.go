// Package realms keeps track of known Docker realms
//
// Realms do not define a permission model and should not be used as such!
// Realms are simply contracts that clients may use to query a set of secrets.
// Once a realm has been established it MUST not change as clients would treat
// the realm as a contract.
// Clients may pin themselves to a specific realm or a group of realms.
//
// Examples:
//
//	`docker/` is a realm for all known Docker secrets.
//	`docker/auth` is a realm for all known Docker Auth secrets.
package realms

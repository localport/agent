package cli

// Tests start unprivileged whatever account runs them, as on an ordinary
// developer or CI account: a test that needs the privileged path takes it
// through asRoot, which fakes the service manager and the system config. An
// elevated Windows run or a root run would otherwise register real services
// and write the machine's device state.
func init() { privilegedProcess = func() bool { return false } }

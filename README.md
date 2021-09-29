# Special Mode Manager
This component is intended to expose special mode settings: Manufacturing mode
and validation unsecure mode.

## Manufacturing Mode
The OpenBMC firmware supports additional IPMI OEM commands available for
Manufacturing usage by means of entering Manufacturing test mode (MTM). OpenBMC
allows all non-intrusive commands and treat the same as any user level
privileges commands. But minimally intrusive and intrusive commands are allowed
only when OpenBMC is in manufacturing mode. A set of commands that are tailored
for the specific manufacturing tests and limited to run in MTM.

* MTM mode which can only be enabled when the BMC Host interface is in
  `Provisioning` mode (i.e. `RestrictionMode` property in interface
  `xyz.openbmc_project.Control.Security.RestrictionMode` must have value set as
  `Provisioning`) and the user demonstrates physical presence by pressing the
  Power button for 15 seconds when AC power is applied to the system.

* Manufacturing command must be executed within 15 minutes from this state
  (Manufacturing mode timeout) after which BMC will mark the Manufacturing mode
  as expired and will not execute any further manufacturing commands.

* Manufacturing Keep alive command can be used to extend the manufacturing
  timeout by 15 minutes.

OpenBMC will exit manufacturing mode if any one of the following conditions are
met.
1. Manufacturing mode timeout of 15 minutes from manufacturing mode state.
2. BMC reboot
3. Entered into any other `Host interface Restriction` other than
   `Provisioning`.

A Redfish event will be logged whenever system entered or exited manufacturing
mode.
* ‘ManufacturingModeEntered’ – Critical severity event
* ‘ManufacturingModeExited’ – OK severity event

“Manufacturing command” means command requiring manufacturing mode.

## Validation Unsecure Mode
For silicon debug & validation purpose, platforms require a feature which can
enable the Manufacturing Mode permanently and in easiest manner. This is
achieved by exposing `SpecialMode` property under
`xyz.openbmc_project.Security.SpecialMode` interface in this component. When
the property is in `ValidationUnsecure` mode, then ManufacturingMode is enabled
permanently, till the property is updated or reset to defaults has been
performed.
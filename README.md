# Chronicle Detection Engine Rules

## What is this?

This is a dedicated `PUBLIC` repo of Chronicle Detection Rules. If you're interested in the private repository, please reach out to me on [twitter](https://twitter.com/dansec_).

These are Chronicle (https://www.chronicle.security) detection rules researched and investigated by Dan Lussier.

All rules have been validated against extremely large datasets and can be pasted into any Chronicle environment with EDR logs, some naming like `Process Launch` may need to be `New Process` otherwise they should overall work.

## Will these work plug & play?

Some of them, yes. But overall you'll need to review your EDR telemetry and make sure the fields map properly. Overall Chronicle's UDM should be fairly consistent, but sometimes certain fields may not work properly. 

I would recommend looking over normal EDR events in your tenant, then matching any fields back that don't match properly.

## What log types are needed?

You'll need at a minimum EDR logs for the majority of these, and a handful will also need proxy/dns logs as well.

## Anything special with EDR?

The majority of these rules, especially ones that detect advanced threat actor behavior, will require enhanced logging, including `Module Load` or `Image Hash`, and `Process Injection`. Make sure this behavior is enabled with your EDR solution.


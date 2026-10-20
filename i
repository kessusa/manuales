Asunto: RE: Global search / FRIDA : conflicting data

Hello Aurelien,

Thanks for the example. Here is how FRIDA resolves labels today for each source and destination IP:

1. Microseg (IV2): if the IP belongs to a workload, we use its microseg labels. This now uses the same rule as Global search (managed workloads, plus unmanaged AVI virtual services "vs-avi*"). This is the fix for EMEAPLAYFLOWS-3868.
2. Otherwise, Playflows: labels come from the Playflows tag.
3. Only when a Playflows label is missing or not a valid value, we try to correct it, in this order: Playflows node comment, Infoblox comment, and ServiceNow (environment only).

So today it is a fallback, not a priority order. When Playflows returns a valid value, as PROD for 10.99.136.96/27, Infoblox is never checked. DPR is not used for labels at the moment (only for the application ID).

Your example also shows a second issue: for subnets like /27, Infoblox and ServiceNow are queried with the subnet instead of an IP, so they probably return nothing.

My proposal, for IPs without microseg labels:
- Query all sources and keep the value from the most reliable one: ServiceNow > DPR > Infoblox > Playflows.
- Flag conflicts in FRIDA, for example "DEV" with a warning icon and a tooltip listing the value from each source.

Before starting, a few questions:
1. Does the priority apply only to the environment, or also to exposure and layer? ServiceNow only gives the environment.
2. Which DPR field should we use for the environment?
3. When sources disagree, should the checks use the winning value, or show the pair as "No info"?
4. For subnets, should we query the subnet itself or its first IP?

Note that querying every source for every IP will add external calls and slow FRIDA down, so we would add caching.

I suggest handling this in a separate ticket, since it changes the logic beyond EMEAPLAYFLOWS-3868. What do you think?

Regards,
Alvaro

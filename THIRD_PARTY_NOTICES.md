# Third-Party Notices

The MeshTransit Core Go module currently includes the following direct runtime
and test dependencies plus their resolved transitive modules. Versions are
resolved by `go.mod` and `go.sum`.

| Module | Version | License |
| --- | --- | --- |
| `github.com/jackc/pgx/v5` | `v5.11.0` | MIT |
| `github.com/prometheus/client_golang` | `v1.24.1` | Apache-2.0 |
| `github.com/redis/go-redis/v9` | `v9.22.0` | BSD-2-Clause |
| `go.uber.org/goleak` (test only) | `v1.3.0` | MIT |
| `golang.org/x/net` | `v0.58.0` | BSD-3-Clause |
| `tailscale.com` | `v1.102.3` | BSD-3-Clause |
| `github.com/beorn7/perks` | `v1.0.1` | MIT |
| `github.com/cespare/xxhash/v2` | `v2.3.0` | MIT |
| `github.com/go-json-experiment/json` | `v0.0.0-20260214004413-d219187c3433` | BSD-3-Clause |
| `github.com/jackc/pgpassfile` | `v1.0.0` | MIT |
| `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | MIT |
| `github.com/jackc/puddle/v2` | `v2.2.2` | MIT |
| `github.com/munnerz/goautoneg` | `v0.0.0-20191010083416-a7dc8b61c822` | BSD-3-Clause |
| `github.com/prometheus/client_model` | `v0.6.2` | Apache-2.0 |
| `github.com/prometheus/common` | `v0.70.1` | Apache-2.0 |
| `github.com/prometheus/procfs` | `v0.21.1` | Apache-2.0 |
| `go.uber.org/atomic` | `v1.11.0` | MIT |
| `go4.org/mem` | `v0.0.0-20240501181205-ae6ca9944745` | Apache-2.0 |
| `golang.org/x/crypto` | `v0.55.0` | BSD-3-Clause |
| `golang.org/x/exp` | `v0.0.0-20260410095643-746e56fc9e2f` | BSD-3-Clause |
| `golang.org/x/sync` | `v0.22.0` | BSD-3-Clause |
| `golang.org/x/sys` | `v0.47.0` | BSD-3-Clause |
| `golang.org/x/text` | `v0.41.0` | BSD-3-Clause |
| `google.golang.org/protobuf` | `v1.36.11` | BSD-3-Clause |

## Compatibility dependency review

`tailscale.com` is pinned to `v1.102.3`, the exact module version used by the
pinned MeshTransit client evidence. Core imports only its Noise handshake and
machine-key packages, exclusively inside `internal/adapter/legacyts2021`; no
domain, application, storage, or public API type depends on that module. The
module is actively maintained and BSD-3-Clause licensed. Every update requires
protocol conformance, race, license, and vulnerability gates. Removing it
requires an independently specified and audited Noise codec behind the same
adapter boundary, without changing product-owned commands.

`golang.org/x/net` is pinned to `v0.58.0` for its supported HTTP/2 `ServeConn`
implementation over an already authenticated Noise connection. It is an
official Go subrepository under BSD-3-Clause. The standard library does not
currently expose an equivalent blocking single-connection server API; removal
becomes practical when it does, with the adapter's conformance tests preserved.

## MIT-licensed components

Copyright (c) 2013-2021 Jack Christensen  
Copyright (c) 2019 Jack Christensen  
Copyright (c) 2020 Jack Christensen  
Copyright (c) 2018 Jack Christensen  
Copyright (c) 2016 Caleb Spare  
Copyright (c) 2016 Uber Technologies, Inc.
Copyright (c) 2013 Blake Mizerany

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## go-redis (BSD-2-Clause)

Copyright (c) 2013 The github.com/redis/go-redis Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## BSD-3-Clause components

Copyright 2009 The Go Authors.
Copyright (c) 2020 Tailscale Inc & contributors.
Copyright (c) 2011 Open Knowledge Foundation Ltd.
Copyright (c) 2018 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Google LLC nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Prometheus components (Apache-2.0)

Prometheus instrumentation library for Go applications  
Copyright 2012-2015 The Prometheus Authors

go4.org/mem  
Copyright 2020 The Go4 AUTHORS

This product includes software developed at SoundCloud Ltd.

The Prometheus components listed above are licensed under the Apache License,
Version 2.0. The full license text is available at
<https://www.apache.org/licenses/LICENSE-2.0>.

## AWS SDK for Go v2 and Smithy Go (Apache-2.0)

Used only by `internal/adapter/sesmail` to send product email through the
Amazon SES v2 API over HTTPS (`github.com/aws/aws-sdk-go-v2`,
`.../credentials`, `.../service/sesv2` and `github.com/aws/smithy-go`).

AWS SDK for Go  
Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.  
Copyright 2014-2015 Stripe, Inc.

Smithy Go  
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

These components are licensed under the Apache License, Version 2.0. The full
license text is available at <https://www.apache.org/licenses/LICENSE-2.0>.

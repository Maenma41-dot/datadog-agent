// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package setup

import pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"

const (
	// ProcmgrEnabled gates whether the dd-procmgr-service Windows service is
	// started by the agent. On Linux the daemon is managed by systemd instead.
	ProcmgrEnabled = "process_manager.enabled"
)

func setupProcmgr(config pkgconfigmodel.Setup) {
	config.BindEnvAndSetDefault(ProcmgrEnabled, false)
}

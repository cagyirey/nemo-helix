// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { useAgentsListDeploymentModes } from '@nemo/sdk/generated/agents/agent-deployments';
import type { DeploymentModeAvailability } from '@nemo/sdk/generated/agents/schema/DeploymentModeAvailability';
import type { DeploymentModeAvailabilityMode } from '@nemo/sdk/generated/agents/schema/DeploymentModeAvailabilityMode';
import { AGENT_CONTAINER_DEPLOYMENTS_ENABLED } from '@studio/constants/environment';
import { useMemo } from 'react';

export type DeploymentMode = DeploymentModeAvailabilityMode;

interface UseDeploymentModesOptions {
  enabled: boolean;
  /** Whether the caller can send an image, so modes without a default image stay usable. */
  canSupplyImage: boolean;
}

const isOffered = (entry: DeploymentModeAvailability, canSupplyImage: boolean): boolean => {
  if (!entry.enabled) return false;
  if (entry.mode === 'subprocess') return true;
  return AGENT_CONTAINER_DEPLOYMENTS_ENABLED && (canSupplyImage || !entry.requires_image);
};

/** The deployment modes this platform can run, in server order, always including subprocess. */
export const useDeploymentModes = (
  workspace: string,
  { enabled, canSupplyImage }: UseDeploymentModesOptions
): { modes: DeploymentMode[]; isLoading: boolean; isReady: boolean } => {
  const { data, isLoading } = useAgentsListDeploymentModes(workspace, { query: { enabled } });
  const modes = useMemo(() => {
    const offered = (data?.data ?? [])
      .filter((entry) => isOffered(entry, canSupplyImage))
      .map((entry) => entry.mode);
    // The server always runs subprocess, so it is the safe choice before the list loads.
    return offered.includes('subprocess') ? offered : ['subprocess' as const, ...offered];
  }, [data, canSupplyImage]);
  return { modes, isLoading, isReady: data !== undefined };
};

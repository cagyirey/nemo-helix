// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AUTH_AUTHORITY,
  AUTH_CLIENT_ID,
  OIDC_TOKEN_ENDPOINT_AUTH_METHOD,
} from '@studio/constants/environment';
import { useEffect, useState } from 'react';
import { hasAuthParams, useAuth } from 'react-oidc-context';
import { useLocation } from 'react-router';

/**
 * This hook is used to automatically handle the login process.
 *
 * Mirrors logic in useAutoSignin that can be enabled when the AUTH_CLIENT_ID and AUTH_AUTHORITY env vars are set.
 *
 * @returns `isAuthPending` - true when auth is enabled and the user is not yet authenticated (UI should be hidden)
 */
export const useAuthAutoLogin = (): { isAuthPending: boolean } => {
  const auth = useAuth();
  const [hasAttemptedLogin, setHasAttemptedLogin] = useState(false);
  const location = useLocation();
  const isE2E = typeof window !== 'undefined' && window.localStorage.getItem('e2e_test') === 'true';
  const isAuthEnabled = !!(AUTH_CLIENT_ID && AUTH_AUTHORITY);
  const shouldAttemptLogin =
    isAuthEnabled &&
    !hasAttemptedLogin &&
    !hasAuthParams() &&
    !auth?.isAuthenticated &&
    !auth?.activeNavigator &&
    !auth?.isLoading &&
    !isE2E;

  useEffect(() => {
    if (OIDC_TOKEN_ENDPOINT_AUTH_METHOD === 'client_secret_basic' && shouldAttemptLogin) {
      const returnTo = `${location.pathname}${location.search}`;
      window.location.assign(`/apis/auth/v2/login?return_to=${encodeURIComponent(returnTo)}`);
      setHasAttemptedLogin(true);
      return;
    }
    if (shouldAttemptLogin) {
      auth.signinRedirect({
        state: {
          path: location.pathname,
          search: location.search,
        },
      });
      setHasAttemptedLogin(true);
    }
  }, [auth, location, shouldAttemptLogin]);

  // Hide the UI when auth is enabled but the user is not authenticated and we're not handling a callback
  const isAuthPending = isAuthEnabled && !auth?.isAuthenticated && !hasAuthParams() && !isE2E;

  return { isAuthPending };
};

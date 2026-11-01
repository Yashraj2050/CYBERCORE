"use client";

import { useState, useCallback } from "react";
import { ApiError } from "@/lib/api/errors";
import type { ApiResponse } from "@/types/api";

interface UseApiState<T> {
  data: T | null;
  error: ApiError | null;
  isLoading: boolean;
}

/**
 * Reusable hook for executing typed API requests.
 */
export function useApi<T, P extends unknown[] = unknown[]>(
  apiCall: (...args: P) => Promise<ApiResponse<T>>
) {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    error: null,
    isLoading: false,
  });

  const execute = useCallback(
    async (...args: P): Promise<T | null> => {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));
      try {
        const response = await apiCall(...args);
        setState({ data: response.data, error: null, isLoading: false });
        return response.data;
      } catch (err) {
        const apiError =
          err instanceof ApiError
            ? err
            : new ApiError({
                message: err instanceof Error ? err.message : "Unknown error",
                status: 0,
                statusText: "Client Error",
                endpoint: "",
              });

        setState({ data: null, error: apiError, isLoading: false });
        return null;
      }
    },
    [apiCall]
  );

  const reset = useCallback(() => {
    setState({ data: null, error: null, isLoading: false });
  }, []);

  return {
    ...state,
    execute,
    reset,
  };
}


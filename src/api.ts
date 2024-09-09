
/**
	 * Helper function to get attestation from a BAP API server
	 *
	 * @param apiUrl
	 * @param apiData
	 * @returns {Promise<any>}
	 */
export const getApiData = async <T>(apiUrl: string, apiData: unknown, server: string, token: string): Promise<T> => {
  const url = `${server}${apiUrl}`;
  const response = await fetch(url, {
    method: "post",
    headers: {
      "Content-type": "application/json; charset=utf-8",
      token,
      format: "json",
    },
    body: JSON.stringify(apiData),
  });

  return response.json();
}

export type APIFetcher = <T>(url: string, data: unknown) => Promise<T>;

export const apiFetcher = (host: string, token: string): APIFetcher => async <T>(url: string, data: unknown): Promise<T> => {
  return getApiData<T>(url, data, host, token);
}
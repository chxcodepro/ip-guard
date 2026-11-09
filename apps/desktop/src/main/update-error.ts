export function updateFailure(error: unknown) {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  const code =
    error !== null && typeof error === "object" && "code" in error && typeof error.code === "string"
      ? error.code
      : "";
  const directStatus =
    error !== null &&
    typeof error === "object" &&
    "statusCode" in error &&
    typeof error.statusCode === "number"
      ? error.statusCode
      : undefined;
  const status =
    directStatus ??
    Number(/(?:HttpError:\s*|HTTP_ERROR_|HTTP\s+)(\d{3})\b/i.exec(`${code} ${message}`)?.[1]);
  const detail = `${code} ${message}`;
  if (
    status === 408 ||
    status === 504 ||
    /\b(?:ERR_(?:CONNECTION_TIMED_OUT|TIMED_OUT)|ETIMEDOUT)\b|request timed out/i.test(detail)
  )
    return {
      retryable: true,
      message: `GitHub 连接超时${Number.isFinite(status) ? `（HTTP ${status}）` : ""}，请稍后重试。`,
    };
  if (status >= 500 && status <= 599)
    return { retryable: true, message: `GitHub 暂时不可用（HTTP ${status}），请稍后重试。` };
  if (
    /\b(?:ERR_(?:NETWORK_CHANGED|PROXY_CONNECTION_FAILED|CONNECTION_RESET|CONNECTION_CLOSED|CONNECTION_ABORTED|INTERNET_DISCONNECTED|NAME_NOT_RESOLVED|TUNNEL_CONNECTION_FAILED|ADDRESS_UNREACHABLE)|ECONNRESET|ECONNREFUSED|EPIPE|EAI_AGAIN|ENOTFOUND)\b/i.test(
      detail,
    )
  )
    return { retryable: true, message: "GitHub 连接暂时失败，请确认网络或代理已连接。" };
  if (/ERR_CERT_|CERT_|SELF_SIGNED/i.test(detail))
    return { retryable: false, message: "GitHub 证书校验失败，请检查系统时间或代理证书。" };
  if (status === 429) return { retryable: false, message: "GitHub 请求过于频繁，请稍后再检查。" };
  if (status === 401 || status === 403)
    return {
      retryable: false,
      message: `GitHub 拒绝访问（HTTP ${status}），请检查网络或更新源权限。`,
    };
  if (/ERR_UPDATER_CHANNEL_FILE_NOT_FOUND/.test(detail))
    return { retryable: false, message: "新版发布文件尚未就绪，请稍后重试或查看 Releases。" };
  if (status === 404)
    return {
      retryable: false,
      message: "GitHub 更新源或发布文件暂不可用（HTTP 404），请查看 Releases。",
    };
  if (/ERR_UPDATER_(?:CHECKSUM_MISMATCH|INVALID_SIGNATURE)/.test(detail))
    return { retryable: false, message: "更新包校验失败，请重新下载或从 Releases 获取安装包。" };
  return { retryable: false, message: "更新操作失败，请稍后重试或打开 Releases。" };
}

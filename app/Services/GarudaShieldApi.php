<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Http\Client\ConnectionException;
use JsonException;

class GarudaShieldApi
{
    public function get(string $path, array $query = [], int $timeout = 5): array
    {
        return $this->request('GET', $path, $query, $timeout);
    }

    public function post(string $path, int $timeout = 12): array
    {
        return $this->request('POST', $path, [], $timeout);
    }

    public function startAlertAnalysis(string $id): array
    {
        return $this->post('/api/v1/alerts/'.rawurlencode($id).'/analyze', 12);
    }

    public function alertAnalysis(string $id): array
    {
        return $this->get('/api/v1/alerts/'.rawurlencode($id).'/analysis', [], 8);
    }

    private function request(string $method, string $path, array $query, int $timeout): array
    {
        $base = rtrim((string) config('services.garudashield.url'), '/');
        if ($base === '') {
            Log::error('GarudaShield API URL is not configured', ['endpoint' => $path]);
            return $this->failure('Base URL API belum dikonfigurasi. Atur GARUDASHIELD_API_URL di .env.');
        }
        $parts = parse_url($base);
        if (! filter_var($base, FILTER_VALIDATE_URL) || ! in_array($parts['scheme'] ?? null, ['http', 'https'], true) || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            Log::error('GarudaShield API URL is invalid', ['endpoint' => $path]);
            return $this->failure('GARUDASHIELD_API_URL tidak valid.');
        }
        try {
            $pending = Http::acceptJson()->connectTimeout(2)->timeout($timeout);
            $url = $base.'/'.ltrim($path, '/');
            $response = strtoupper($method) === 'POST'
                ? $pending->post($url)
                : $pending->get($url, $query);
        } catch (ConnectionException $e) {
            Log::warning('GarudaShield API connection failed', ['endpoint' => $path, 'exception' => $e::class]);
            return $this->failure('Tidak dapat terhubung ke API detection engine. Periksa alamat API dan pastikan layanannya berjalan.');
        } catch (\Throwable $e) {
            Log::error('GarudaShield API request failed unexpectedly', ['endpoint' => $path, 'exception' => $e::class]);
            return $this->failure('Terjadi kesalahan saat meminta data dari API detection engine.');
        }

        if (! $response->successful()) {
            Log::warning('GarudaShield API returned an HTTP error', ['endpoint' => $path, 'status' => $response->status()]);
            return $this->failure('API detection engine mengembalikan HTTP '.$response->status().'.') + ['http_status' => $response->status()];
        }

        try {
            $data = json_decode($response->body(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            Log::warning('GarudaShield API returned invalid JSON', ['endpoint' => $path, 'exception' => $e::class]);
            return $this->failure('API detection engine mengembalikan JSON yang tidak valid.');
        }
        if (! is_array($data)) {
            Log::warning('GarudaShield API returned an unexpected JSON type', ['endpoint' => $path, 'json_type' => get_debug_type($data)]);
            return $this->failure('Respons JSON API detection engine memiliki format yang tidak sesuai.');
        }

        return ['ok' => true, 'data' => $data, 'message' => null];
    }

    public function summary(): array
    {
        $result = $this->get('/api/v1/dashboard/summary');
        if (! $result['ok']) return $result;

        $required = ['total_events', 'total_alerts', 'open_alerts', 'failed_login_events', 'successful_login_events', 'critical_open_alerts', 'high_risk_open_alerts', 'average_open_alert_risk_score'];
        foreach ($required as $field) {
            if (! array_key_exists($field, $result['data']) || ! is_numeric($result['data'][$field])) {
                return $this->invalidShape('/api/v1/dashboard/summary', 'missing or non-numeric field: '.$field);
            }
        }
        return $result;
    }

    public function health(): array
    {
        $result = $this->get('/health');
        if (! $result['ok']) return $result;

        if (($result['data']['status'] ?? null) !== 'ok' || ! isset($result['data']['version']) || ! is_string($result['data']['version'])) {
            return $this->invalidShape('/health', 'expected status=ok and a version string');
        }
        return $result;
    }

    public function alerts(): array
    {
        $result = $this->get('/api/v1/alerts');
        if (! $result['ok']) return $result;

        if (! isset($result['data']['alerts']) || ! is_array($result['data']['alerts']) || ! array_is_list($result['data']['alerts']) || ! $this->isRowList($result['data']['alerts'])) {
            return $this->invalidShape('/api/v1/alerts', 'expected an alerts array containing objects');
        }
        return $result;
    }

    public function events(int $limit = 50): array
    {
        $result = $this->get('/api/v1/events', ['limit' => $limit]);
        if (! $result['ok']) return $result;

        $rows = $this->eventRows($result['data']);
        if ($rows === null || ! $this->isRowList($rows)) {
            return $this->invalidShape('/api/v1/events', 'expected an events array containing objects');
        }
        $result['rows'] = $rows;
        return $result;
    }

    private function eventRows(array $data): ?array
    {
        if (array_is_list($data)) return $data;
        $nested = $data['data'] ?? null;
        $candidates = [$data['events'] ?? null, $data['items'] ?? null];
        if (is_array($nested)) {
            $candidates[] = $nested['events'] ?? null;
            $candidates[] = $nested;
        }
        foreach ($candidates as $rows) {
            if (is_array($rows) && array_is_list($rows)) return $rows;
        }
        return null;
    }

    private function isRowList(array $rows): bool
    {
        foreach ($rows as $row) if (! is_array($row) || array_is_list($row)) return false;
        return true;
    }

    private function invalidShape(string $endpoint, string $reason): array
    {
        Log::warning('GarudaShield API response did not match the expected schema', ['endpoint' => $endpoint, 'reason' => $reason]);
        return $this->failure('API merespons, tetapi struktur datanya tidak sesuai. Periksa format respons endpoint di detection engine.');
    }

    private function failure(string $message): array
    {
        return ['ok' => false, 'data' => [], 'message' => $message];
    }

    public function value(array $data, array $keys): mixed
    {
        foreach ($keys as $key) {
            $value = data_get($data, $key);
            if ($value !== null && $value !== '') return $value;
        }
        return null;
    }

    public function humanType(mixed $type): string
    {
        return Str::of((string) $type)->replace('_', ' ')->lower()->ucfirst()->toString();
    }
}

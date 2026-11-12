<?php

namespace App\Services;

use Carbon\CarbonImmutable;
use Throwable;

/** Converts timezone-aware API timestamps for display without guessing naive timestamps. */
class TimestampPresenter
{
    private const DISPLAY_TIMEZONE = 'Asia/Jakarta';

    public function parse(mixed $value): ?CarbonImmutable
    {
        if (! is_string($value) || trim($value) === '') return null;
        $value = trim($value);

        $hasExplicitTimezone = preg_match('/(?:Z|[+-](?:0\d|1\d|2[0-3]):?[0-5]\d)$/i', $value) === 1;
        $timezone = $hasExplicitTimezone ? null : config('services.garudashield.naive_timestamp_timezone');
        if (! $hasExplicitTimezone && (! is_string($timezone) || $timezone === '')) return null;

        try {
            return CarbonImmutable::parse($value, $timezone);
        } catch (Throwable) {
            return null;
        }
    }

    public function format(mixed $value): string
    {
        if (! is_string($value) || trim($value) === '') return '—';
        $parsed = $this->parse($value);
        if (! $parsed) {
            $label = preg_match('/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/', trim($value))
                ? 'zona waktu tidak diketahui'
                : 'timestamp tidak valid';
            return trim($value).' ('.$label.')';
        }

        return $parsed->setTimezone(self::DISPLAY_TIMEZONE)
            ->locale('id')
            ->translatedFormat('d M Y, H:i:s').' WIB';
    }

    /** Sort known instants newest first, retain API order among timestamps we cannot interpret. */
    public function newestFirst(array $rows, array $timestampKeys): array
    {
        $decorated = [];
        foreach (array_values($rows) as $index => $row) {
            $raw = null;
            if (is_array($row)) {
                foreach ($timestampKeys as $key) {
                    $candidate = data_get($row, $key);
                    if ($candidate !== null && $candidate !== '') {
                        $raw = $candidate;
                        break;
                    }
                }
            }
            $instant = $this->parse($raw);
            $decorated[] = ['row' => $row, 'index' => $index, 'instant' => $instant?->format('U.u')];
        }

        usort($decorated, static function (array $left, array $right): int {
            if ($left['instant'] === null || $right['instant'] === null) {
                if ($left['instant'] === $right['instant']) return $left['index'] <=> $right['index'];
                return $left['instant'] === null ? 1 : -1;
            }
            $byTime = (float) $right['instant'] <=> (float) $left['instant'];
            return $byTime !== 0 ? $byTime : $left['index'] <=> $right['index'];
        });

        return array_values(array_map(static fn (array $item) => $item['row'], $decorated));
    }
}

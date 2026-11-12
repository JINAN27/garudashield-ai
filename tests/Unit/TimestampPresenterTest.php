<?php

namespace Tests\Unit;

use App\Services\TimestampPresenter;
use Tests\TestCase;

class TimestampPresenterTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['services.garudashield.naive_timestamp_timezone' => null]);
    }

    public function test_utc_timestamp_formats_as_wib(): void
    {
        $this->assertSame('12 Nov 2026, 08:30:15 WIB', app(TimestampPresenter::class)->format('2026-11-12T01:30:15Z'));
    }

    public function test_explicit_non_utc_offset_is_converted_to_wib(): void
    {
        $this->assertSame('12 Nov 2026, 08:30:15 WIB', app(TimestampPresenter::class)->format('2026-11-12T05:00:15+03:30'));
    }

    public function test_wib_offset_is_not_converted_twice(): void
    {
        $this->assertSame('12 Nov 2026, 08:30:15 WIB', app(TimestampPresenter::class)->format('2026-11-12T08:30:15+07:00'));
    }

    public function test_timezone_naive_timestamp_is_not_guessed_without_a_configured_policy(): void
    {
        $presenter = app(TimestampPresenter::class);
        $this->assertNull($presenter->parse('2026-11-12 08:30:15'));
        $this->assertSame('2026-11-12 08:30:15 (zona waktu tidak diketahui)', $presenter->format('2026-11-12 08:30:15'));
    }

    public function test_naive_timestamp_can_use_an_explicit_configured_timezone_policy(): void
    {
        config(['services.garudashield.naive_timestamp_timezone' => 'UTC']);
        $this->assertSame('12 Nov 2026, 08:30:15 WIB', app(TimestampPresenter::class)->format('2026-11-12 01:30:15'));
    }

    public function test_missing_and_invalid_timestamps_have_safe_placeholders(): void
    {
        $presenter = app(TimestampPresenter::class);
        $this->assertSame('—', $presenter->format(null));
        $this->assertSame('not-a-time (timestamp tidak valid)', $presenter->format('not-a-time'));
    }

    public function test_newest_first_orders_aware_timestamps_and_retains_unknown_rows_last(): void
    {
        $rows = [
            ['id' => 'older', 'timestamp' => '2026-11-12T01:00:00Z'],
            ['id' => 'newer', 'timestamp' => '2026-11-12T09:00:00+07:00'],
            ['id' => 'unknown', 'timestamp' => '2026-11-12 12:00:00'],
        ];

        $ordered = app(TimestampPresenter::class)->newestFirst($rows, ['timestamp']);
        $this->assertSame(['newer', 'older', 'unknown'], array_column($ordered, 'id'));
    }
}

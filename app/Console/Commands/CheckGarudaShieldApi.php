<?php

namespace App\Console\Commands;

use App\Services\GarudaShieldApi;
use Illuminate\Console\Command;

class CheckGarudaShieldApi extends Command
{
    protected $signature = 'garudashield:check-api';

    protected $description = 'Check connectivity and response schemas for the GarudaShield detection API';

    public function handle(GarudaShieldApi $api): int
    {
        $health = $api->health();
        $summary = $api->summary();
        $alerts = $api->alerts();
        $events = $api->events(50);
        $results = compact('health', 'summary', 'alerts', 'events');

        foreach ($results as $name => $result) {
            if (! $result['ok']) {
                $this->components->error($name.': '.$result['message']);
                continue;
            }
            $detail = match ($name) {
                'health' => 'healthy · API '.$result['data']['version'],
                'summary' => $result['data']['total_events'].' events · '.$result['data']['total_alerts'].' alerts',
                'alerts' => count($result['data']['alerts']).' alerts parsed',
                'events' => count($result['rows']).' events parsed',
            };
            $this->components->info($name.': '.$detail);
        }

        return collect($results)->every(fn (array $result) => $result['ok']) ? self::SUCCESS : self::FAILURE;
    }
}

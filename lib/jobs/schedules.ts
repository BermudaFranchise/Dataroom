import { logger } from "./logger";

interface ScheduleConfig<TPayload = { timestamp: Date }> {
  id: string;
  cron: string;
  run: (payload: TPayload) => Promise<unknown>;
}

interface ScheduleHandle<TPayload> {
  id: string;
  cron: string;
  run: (payload: TPayload) => Promise<unknown>;
}

export const schedules = {
  task: <TPayload = { timestamp: Date }>(
    config: ScheduleConfig<TPayload>,
  ): ScheduleHandle<TPayload> => {
    logger.debug(`Registered scheduled task: ${config.id} (${config.cron})`);
    return {
      id: config.id,
      cron: config.cron,
      run: config.run,
    };
  },
};

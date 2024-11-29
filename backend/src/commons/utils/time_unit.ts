import { type TimeSpanUnit, TimeSpan } from "oslo";

const timeUnits: TimeSpanUnit[] = ["ms", "s", "m", "h", "d", "w"];
const pattern = new RegExp(
  String.raw`^(?<duration>\d+)(?<unit>${timeUnits.join("|")})$`,
);

export function isSupportedTimeUnit(value: string) {
  return pattern.test(value);
}

export function parseStrTimeUnit(value: string) {
  if (!isSupportedTimeUnit(value)) {
    return null;
  }

  const [, duration, unit] = pattern.exec(value)!;
  return new TimeSpan(Number(duration), unit as TimeSpanUnit);
}

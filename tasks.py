from config import Config
from extensions import scheduler


def start_scheduler(app):
    # Start APScheduler with a job that generates and processes an event on an interval.
    from generator import generate_event
    from app import process_event

    def job():
        with app.app_context():
            event = generate_event()
            process_event(event)

    if not scheduler.running:
        scheduler.add_job(
            job,
            "interval",
            seconds=Config.GENERATOR_INTERVAL_SECONDS,
            id="event_generator",
            replace_existing=True,
            max_instances=1,
        )
        scheduler.start()
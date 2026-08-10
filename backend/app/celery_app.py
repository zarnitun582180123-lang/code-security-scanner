from celery import Celery

celery_app = Celery(
    "worker",
    broker="redis://127.0.0.1:6379/0",
    backend="redis://127.0.0.1:6379/0",
    include=["app.tasks"]  # Celery Worker တက်တာနဲ့ app/tasks.py ထဲက Task ကို Auto Load လုပ်ခိုင်းခြင်း
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    redis_backend_use_ssl=False,
    redis_backend_transport_options={"protocol": 2},
    broker_transport_options={"protocol": 2}
)
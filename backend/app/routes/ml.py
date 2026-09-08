from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.ml.ml_detector import predict_vulnerability


router = APIRouter(
    prefix="/api/ml",
    tags=["Machine Learning"]
)


class MLScanRequest(BaseModel):
    code: str


@router.post("/scan")
def ml_scan(request: MLScanRequest):

    try:
        result = predict_vulnerability(request.code)

        return {
            "success": True,
            "result": result
        }

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"ML analysis failed: {str(e)}"
        )
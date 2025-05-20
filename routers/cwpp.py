from fastapi import APIRouter, HTTPException
from cwpp import runtime_monitor
from cwpp.runtime_monitor import RuntimeEventResponse  # We’ll create this next
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/monitor/runtime", response_model=RuntimeEventResponse)
def runtime_monitoring():
    try:
        logger.info("Fetching simulated runtime events...")
        result = runtime_monitor.simulate_runtime_events()
        return {"message": "Runtime events fetched successfully", "data": result}
    except AttributeError as e:
        logger.error(f"Attribute error: {e}")
        raise HTTPException(status_code=500, detail="Runtime monitor function missing")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

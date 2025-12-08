use alloc::sync::Arc;

use miden_core::{
    EventId, Operation,
    mast::{BasicBlockNode, MastForest, MastNodeId, OpBatch},
    sys_events::SystemEvent,
};

use crate::{
    AsyncHost, ErrorContext, ExecutionError,
    continuation_stack::ContinuationStack,
    err_ctx,
    fast::{FastProcessor, Tracer, trace_state::NodeExecutionState},
    operations::sys_ops::sys_event_handlers::handle_system_event,
    processor::Processor,
};

impl FastProcessor {
    /// Execute the given basic block node.
    ///
    /// # Arguments
    /// * `node_id` - The ID of this basic block node in the `current_forest` MAST forest. This
    ///   should match the ID in `basic_block_node.decorators` when it's `Linked`.
    #[inline(always)]
    pub(super) async fn execute_basic_block_node_from_start(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::Start(node_id),
            continuation_stack,
            current_forest,
        );

        // Execute decorators that should be executed before entering the node
        self.execute_before_enter_decorators(node_id, current_forest, host)?;

        // Corresponds to the row inserted for the BASIC BLOCK operation added to the trace.
        self.increment_clk(tracer);

        // execute first batch
        if let Some(first_op_batch) = basic_block_node.op_batches().first() {
            self.execute_op_batch(
                basic_block_node,
                first_op_batch,
                0,
                0,
                0,
                host,
                continuation_stack,
                current_forest,
                tracer,
            )
            .await?;
        }

        // execute the rest of the batches
        self.execute_basic_block_node_from_batch(
            basic_block_node,
            node_id,
            1,
            host,
            continuation_stack,
            current_forest,
            tracer,
        )
        .await
    }

    /// Executes the give basic block node starting from the RESPAN preceding the specified batch.
    #[inline(always)]
    pub(super) async fn execute_basic_block_node_from_batch(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        start_batch_index: usize,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let mut batch_offset_in_block = basic_block_node
            .op_batches()
            .iter()
            .take(start_batch_index)
            .map(|batch| batch.ops().len())
            .sum();

        // execute the rest of the op batches
        for (batch_index, op_batch) in
            basic_block_node.op_batches().iter().enumerate().skip(start_batch_index)
        {
            // RESPAN
            {
                tracer.start_clock_cycle(
                    self,
                    NodeExecutionState::Respan { node_id, batch_index },
                    continuation_stack,
                    current_forest,
                );

                // Corresponds to the RESPAN operation added to the trace.
                self.increment_clk(tracer);
            }

            self.execute_op_batch(
                basic_block_node,
                op_batch,
                batch_index,
                0,
                batch_offset_in_block,
                host,
                continuation_stack,
                current_forest,
                tracer,
            )
            .await?;
            batch_offset_in_block += op_batch.ops().len();
        }

        self.finish_basic_block(
            basic_block_node,
            node_id,
            current_forest,
            host,
            continuation_stack,
            tracer,
        )
    }

    /// Executes the give basic block node starting from the RESPAN preceding the specified batch.
    #[inline(always)]
    pub(super) async fn execute_basic_block_node_from_op_idx(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        start_batch_index: usize,
        start_op_idx_in_batch: usize,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        let batch_offset_in_block = basic_block_node
            .op_batches()
            .iter()
            .take(start_batch_index)
            .map(|batch| batch.ops().len())
            .sum();

        // Finish executing the specified batch from the given op index
        self.execute_op_batch(
            basic_block_node,
            &basic_block_node.op_batches()[start_batch_index],
            start_batch_index,
            start_op_idx_in_batch,
            batch_offset_in_block,
            host,
            continuation_stack,
            current_forest,
            tracer,
        )
        .await?;

        // Execute the rest of the batches
        self.execute_basic_block_node_from_batch(
            basic_block_node,
            node_id,
            start_batch_index + 1,
            host,
            continuation_stack,
            current_forest,
            tracer,
        )
        .await
    }

    /// Executes a single operation batch within a basic block node, starting from the operation
    /// index `start_op_idx`.
    #[inline(always)]
    #[expect(clippy::too_many_arguments)]
    async fn execute_op_batch(
        &mut self,
        basic_block: &BasicBlockNode,
        batch: &OpBatch,
        batch_index: usize,
        start_op_idx: usize,
        batch_offset_in_block: usize,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        current_forest: &Arc<MastForest>,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        // execute operations in the batch one by one
        for (op_idx_in_batch, op) in batch.ops().iter().enumerate().skip(start_op_idx) {
            let op_idx_in_block = batch_offset_in_block + op_idx_in_batch;

            // Use the forest's decorator storage to get decorators for this operation
            let node_id = basic_block
                .linked_id()
                .expect("basic block node should be linked when executing operations");
            for decorator in current_forest.decorators_for_op(node_id, op_idx_in_block) {
                self.execute_decorator(decorator, host)?;
            }

            // if in trace mode, check if we need to record a trace state before executing the
            // operation
            tracer.start_clock_cycle(
                self,
                NodeExecutionState::BasicBlock { node_id, batch_index, op_idx_in_batch },
                continuation_stack,
                current_forest,
            );

            // Execute the operation.
            //
            // Note: we handle the `Emit` operation separately, because it is an async operation,
            // whereas all the other operations are synchronous (resulting in a significant
            // performance improvement).
            {
                let err_ctx = err_ctx!(current_forest, node_id, host, op_idx_in_block);
                match op {
                    Operation::Emit => self.op_emit(host, &err_ctx).await?,
                    _ => {
                        // if the operation is not an Emit, we execute it normally
                        self.execute_sync_op(
                            op,
                            op_idx_in_block,
                            current_forest,
                            host,
                            &err_ctx,
                            tracer,
                        )?;
                    },
                }
            }

            self.increment_clk(tracer);
        }

        Ok(())
    }

    #[inline(always)]
    async fn op_emit(
        &mut self,
        host: &mut impl AsyncHost,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        let mut process = self.state();
        let event_id = EventId::from_felt(process.get_stack_item(0));

        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            handle_system_event(&mut process, system_event, err_ctx)
        } else {
            let clk = process.clk();
            let mutations = host.on_event(&process).await.map_err(|err| {
                let event_name = host.resolve_event(event_id).cloned();
                ExecutionError::event_error(err, event_id, event_name, err_ctx)
            })?;
            self.advice
                .apply_mutations(mutations)
                .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;
            Ok(())
        }
    }

    /// Execute the finish phase of a basic block node.
    #[inline(always)]
    pub(super) fn finish_basic_block(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        host: &mut impl AsyncHost,
        continuation_stack: &mut ContinuationStack,
        tracer: &mut impl Tracer,
    ) -> Result<(), ExecutionError> {
        tracer.start_clock_cycle(
            self,
            NodeExecutionState::End(node_id),
            continuation_stack,
            current_forest,
        );

        // Corresponds to the row inserted for the END operation added to the trace.
        self.increment_clk(tracer);

        self.execute_end_of_block_decorators(basic_block_node, node_id, current_forest, host)?;
        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    // Executes any decorators which have not been executed during span ops execution; this can
    // happen for decorators appearing after all operations in a block. these decorators are
    // executed after BASIC BLOCK is closed to make sure the VM clock cycle advances beyond the last
    // clock cycle of the BASIC BLOCK ops. For the linked case, check for decorators at an operation
    // index beyond the last operation
    #[inline(always)]
    pub(super) fn execute_end_of_block_decorators(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        host: &mut impl AsyncHost,
    ) -> Result<(), ExecutionError> {
        let num_ops = basic_block_node.num_operations() as usize;
        for decorator in current_forest.decorators_for_op(node_id, num_ops) {
            self.execute_decorator(decorator, host)?;
        }
        Ok(())
    }
}

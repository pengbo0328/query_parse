#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pool_type.h"
#include "utils/palloc.h"
#include "utils/elog.h"
#include "parser.h"
#include "extensible.h"
#include "pool_string.h"
#include "pg_list.h"
#include "parsenodes.h"
#include "pg_class.h"
#include "pg_trigger.h"
#include "value.h"
#include "../pool_config.h"
#include "context/pool_session_context.h"
#include "context/pool_query_context.h"
#include "utils/pool_select_walker.h"
#include "utils/pool_relcache.h"

/*
 * Where to send query
 */
typedef enum
{
	POOL_PRIMARY,
	POOL_STANDBY,
	POOL_EITHER,
	POOL_BOTH
}			POOL_DEST;

static bool function_call_walker(Node *node, void *context);
static bool insertinto_or_locking_clause_walker(Node *node, void *context);
static char *strip_quote(char *str);
extern int  pattern_compare(char *str, const int type, const char *param_name);
extern POOL_DEST send_to_where(Node *node, char *query);
extern void is_read_or_write_query(Node *node, char *query);
bool raw_expression_tree_walker(Node *node, bool (*walker) (), void *context);

/*==========================================================================*/
/* FUNCTION                                                                 */
/*==========================================================================*/
/*
 * Return true if this SELECT has function calls *and* supposed to
 * modify database.  We check black/white function list to determine
 * whether the function modifies database.
 */
bool
pool_has_function_call(Node *node)
{
    SelectContext ctx; 

    if (!IsA(node, SelectStmt))
        return false;

    ctx.has_function_call = false;
    ctx.pg_terminate_backend_pid = -1;

    raw_expression_tree_walker(node, function_call_walker, &ctx);

    return ctx.has_function_call;
}

/*
 * Walker function to find a function call which is supposed to write
 * database.
 */
static bool
function_call_walker(Node *node, void *context)
{
	SelectContext *ctx = (SelectContext *) context;

	if (node == NULL)
		return false;

	if (IsA(node, FuncCall))
	{
		FuncCall   *fcall = (FuncCall *) node;
		char	   *fname = NULL;
		int			length = list_length(fcall->funcname);

		if (length > 0)
		{
			if (length == 1)	/* no schema qualification? */
			{
				fname = strVal(linitial(fcall->funcname));
			}
			else
			{
				fname = strVal(lsecond(fcall->funcname));	/* with schema
															 * qualification */
			}
			
			/* XXX */
			printf("function call walker, function name: %s\n", fname);

			ereport(DEBUG1,
					(errmsg("function call walker, function name: \"%s\"", fname)));

			if (ctx->pg_terminate_backend_pid == 0 && strcmp("pg_terminate_backend", fname) == 0)
			{
				if (list_length(fcall->args) == 1)
				{
					Node	   *arg = linitial(fcall->args);

					if (IsA(arg, A_Const) &&
						((A_Const *) arg)->val.type == T_Integer)
					{
						ctx->pg_terminate_backend_pid = ((A_Const *) arg)->val.val.ival;
						ereport(DEBUG1,
								(errmsg("pg_terminate_backend pid = %d", ctx->pg_terminate_backend_pid)));
					}
				}
			}

			/*
			 * Check white list if any.
			 */
			if (pool_config->num_white_function_list > 0)
			{
				/* Search function in the white list regex patterns */
				if (pattern_compare(fname, WHITELIST, "white_function_list") == 1)
				{
					/*
					 * If the function is found in the white list, we can
					 * ignore it
					 */
					return raw_expression_tree_walker(node, function_call_walker, context);
				}

				/*
				 * Since the function was not found in white list, we have
				 * found a writing function.
				 */
				ctx->has_function_call = true;
				return false;
			}

			/*
			 * Check black list if any.
			 */
			if (pool_config->num_black_function_list > 0)
			{
				/* Search function in the black list regex patterns */
				if (pattern_compare(fname, BLACKLIST, "black_function_list") == 1)
				{
					/* Found. */
					ctx->has_function_call = true;
					return false;
				}
			}
		}
	}
	return raw_expression_tree_walker(node, function_call_walker, context);
}

/* from nodeFuncs.c start */

/*
 * raw_expression_tree_walker --- walk raw parse trees
 *
 * This has exactly the same API as expression_tree_walker, but instead of
 * walking post-analysis parse trees, it knows how to walk the node types
 * found in raw grammar output.  (There is not currently any need for a
 * combined walker, so we keep them separate in the name of efficiency.)
 * Unlike expression_tree_walker, there is no special rule about query
 * boundaries: we descend to everything that's possibly interesting.
 *
 * Currently, the node type coverage extends to SelectStmt and everything
 * that could appear under it, but not other statement types.
 */
bool
raw_expression_tree_walker(Node *node,
						   bool (*walker) (),
						   void *context)
{
	ListCell   *temp;

	/*
	 * The walker has already visited the current node, and so we need only
	 * recurse into any sub-nodes it has.
	 */
	if (node == NULL)
		return false;

	/* Guard against stack overflow due to overly complex expressions */

	/*
	 * check_stack_depth();
	 */

	switch (nodeTag(node))
	{
		case T_SetToDefault:
		case T_CurrentOfExpr:
		case T_Integer:
		case T_Float:
		case T_String:
		case T_BitString:
		case T_Null:
		case T_ParamRef:
		case T_A_Const:
		case T_A_Star:
			/* primitive node types with no subnodes */
			break;
		case T_Alias:
			/* we assume the colnames list isn't interesting */
			break;
		case T_RangeVar:
			return walker(((RangeVar *) node)->alias, context);
		case T_GroupingFunc:
			return walker(((GroupingFunc *) node)->args, context);
		case T_SubLink:
			{
				SubLink    *sublink = (SubLink *) node;

				if (walker(sublink->testexpr, context))
					return true;
				/* we assume the operName is not interesting */
				if (walker(sublink->subselect, context))
					return true;
			}
			break;
		case T_CaseExpr:
			{
				CaseExpr   *caseexpr = (CaseExpr *) node;

				if (walker(caseexpr->arg, context))
					return true;
				/* we assume walker doesn't care about CaseWhens, either */
				foreach(temp, caseexpr->args)
				{
					CaseWhen   *when = (CaseWhen *) lfirst(temp);

					Assert(IsA(when, CaseWhen));
					if (walker(when->expr, context))
						return true;
					if (walker(when->result, context))
						return true;
				}
				if (walker(caseexpr->defresult, context))
					return true;
			}
			break;
		case T_RowExpr:
			/* Assume colnames isn't interesting */
			return walker(((RowExpr *) node)->args, context);
		case T_CoalesceExpr:
			return walker(((CoalesceExpr *) node)->args, context);
		case T_MinMaxExpr:
			return walker(((MinMaxExpr *) node)->args, context);
		case T_XmlExpr:
			{
				XmlExpr    *xexpr = (XmlExpr *) node;

				if (walker(xexpr->named_args, context))
					return true;
				/* we assume walker doesn't care about arg_names */
				if (walker(xexpr->args, context))
					return true;
			}
			break;
		case T_NullTest:
			return walker(((NullTest *) node)->arg, context);
		case T_BooleanTest:
			return walker(((BooleanTest *) node)->arg, context);
		case T_JoinExpr:
			{
				JoinExpr   *join = (JoinExpr *) node;

				if (walker(join->larg, context))
					return true;
				if (walker(join->rarg, context))
					return true;
				if (walker(join->quals, context))
					return true;
				if (walker(join->alias, context))
					return true;
				/* using list is deemed uninteresting */
			}
			break;
		case T_IntoClause:
			{
				IntoClause *into = (IntoClause *) node;

				if (walker(into->rel, context))
					return true;
				/* colNames, options are deemed uninteresting */
				/* viewQuery should be null in raw parsetree, but check it */
				if (walker(into->viewQuery, context))
					return true;
			}
			break;
		case T_List:
			foreach(temp, (List *) node)
			{
				if (walker((Node *) lfirst(temp), context))
					return true;
			}
			break;
		case T_InsertStmt:
			{
				InsertStmt *stmt = (InsertStmt *) node;

				if (walker(stmt->relation, context))
					return true;
				if (walker(stmt->cols, context))
					return true;
				if (walker(stmt->selectStmt, context))
					return true;
				if (walker(stmt->onConflictClause, context))
					return true;
				if (walker(stmt->returningList, context))
					return true;
				if (walker(stmt->withClause, context))
					return true;
			}
			break;
		case T_DeleteStmt:
			{
				DeleteStmt *stmt = (DeleteStmt *) node;

				if (walker(stmt->relation, context))
					return true;
				if (walker(stmt->usingClause, context))
					return true;
				if (walker(stmt->whereClause, context))
					return true;
				if (walker(stmt->returningList, context))
					return true;
				if (walker(stmt->withClause, context))
					return true;
			}
			break;
		case T_UpdateStmt:
			{
				UpdateStmt *stmt = (UpdateStmt *) node;

				if (walker(stmt->relation, context))
					return true;
				if (walker(stmt->targetList, context))
					return true;
				if (walker(stmt->whereClause, context))
					return true;
				if (walker(stmt->fromClause, context))
					return true;
				if (walker(stmt->returningList, context))
					return true;
				if (walker(stmt->withClause, context))
					return true;
			}
			break;
		case T_SelectStmt:
			{
				SelectStmt *stmt = (SelectStmt *) node;

				if (walker(stmt->distinctClause, context))
					return true;
				if (walker(stmt->intoClause, context))
					return true;
				if (walker(stmt->targetList, context))
					return true;
				if (walker(stmt->fromClause, context))
					return true;
				if (walker(stmt->whereClause, context))
					return true;
				if (walker(stmt->groupClause, context))
					return true;
				if (walker(stmt->havingClause, context))
					return true;
				if (walker(stmt->windowClause, context))
					return true;
				if (walker(stmt->valuesLists, context))
					return true;
				if (walker(stmt->sortClause, context))
					return true;
				if (walker(stmt->limitOffset, context))
					return true;
				if (walker(stmt->limitCount, context))
					return true;
				if (walker(stmt->lockingClause, context))
					return true;
				if (walker(stmt->withClause, context))
					return true;
				if (walker(stmt->larg, context))
					return true;
				if (walker(stmt->rarg, context))
					return true;
			}
			break;
		case T_A_Expr:
			{
				A_Expr	   *expr = (A_Expr *) node;

				if (walker(expr->lexpr, context))
					return true;
				if (walker(expr->rexpr, context))
					return true;
				/* operator name is deemed uninteresting */
			}
			break;
		case T_BoolExpr:
			{
				BoolExpr   *expr = (BoolExpr *) node;

				if (walker(expr->args, context))
					return true;
			}
			break;
		case T_ColumnRef:
			/* we assume the fields contain nothing interesting */
			break;
		case T_FuncCall:
			{
				FuncCall   *fcall = (FuncCall *) node;

				if (walker(fcall->args, context))
					return true;
				if (walker(fcall->agg_order, context))
					return true;
				if (walker(fcall->agg_filter, context))
					return true;
				if (walker(fcall->over, context))
					return true;
				/* function name is deemed uninteresting */
			}
			break;
		case T_NamedArgExpr:
			return walker(((NamedArgExpr *) node)->arg, context);
		case T_A_Indices:
			{
				A_Indices  *indices = (A_Indices *) node;

				if (walker(indices->lidx, context))
					return true;
				if (walker(indices->uidx, context))
					return true;
			}
			break;
		case T_A_Indirection:
			{
				A_Indirection *indir = (A_Indirection *) node;

				if (walker(indir->arg, context))
					return true;
				if (walker(indir->indirection, context))
					return true;
			}
			break;
		case T_A_ArrayExpr:
			return walker(((A_ArrayExpr *) node)->elements, context);
		case T_ResTarget:
			{
				ResTarget  *rt = (ResTarget *) node;

				if (walker(rt->indirection, context))
					return true;
				if (walker(rt->val, context))
					return true;
			}
			break;
		case T_MultiAssignRef:
			return walker(((MultiAssignRef *) node)->source, context);
		case T_TypeCast:
			{
				TypeCast   *tc = (TypeCast *) node;

				if (walker(tc->arg, context))
					return true;
				if (walker(tc->typeName, context))
					return true;
			}
			break;
		case T_CollateClause:
			return walker(((CollateClause *) node)->arg, context);
		case T_SortBy:
			return walker(((SortBy *) node)->node, context);
		case T_WindowDef:
			{
				WindowDef  *wd = (WindowDef *) node;

				if (walker(wd->partitionClause, context))
					return true;
				if (walker(wd->orderClause, context))
					return true;
				if (walker(wd->startOffset, context))
					return true;
				if (walker(wd->endOffset, context))
					return true;
			}
			break;
		case T_RangeSubselect:
			{
				RangeSubselect *rs = (RangeSubselect *) node;

				if (walker(rs->subquery, context))
					return true;
				if (walker(rs->alias, context))
					return true;
			}
			break;
		case T_RangeFunction:
			{
				RangeFunction *rf = (RangeFunction *) node;

				if (walker(rf->functions, context))
					return true;
				if (walker(rf->alias, context))
					return true;
				if (walker(rf->coldeflist, context))
					return true;
			}
			break;
		case T_RangeTableSample:
			{
				RangeTableSample *rts = (RangeTableSample *) node;

				if (walker(rts->relation, context))
					return true;
				/* method name is deemed uninteresting */
				if (walker(rts->args, context))
					return true;
				if (walker(rts->repeatable, context))
					return true;
			}
			break;
		case T_TypeName:
			{
				TypeName   *tn = (TypeName *) node;

				if (walker(tn->typmods, context))
					return true;
				if (walker(tn->arrayBounds, context))
					return true;
				/* type name itself is deemed uninteresting */
			}
			break;
		case T_ColumnDef:
			{
				ColumnDef  *coldef = (ColumnDef *) node;

				if (walker(coldef->typeName, context))
					return true;
				if (walker(coldef->raw_default, context))
					return true;
				if (walker(coldef->collClause, context))
					return true;
				/* for now, constraints are ignored */
			}
			break;
		case T_GroupingSet:
			return walker(((GroupingSet *) node)->content, context);
		case T_LockingClause:
			return walker(((LockingClause *) node)->lockedRels, context);
		case T_XmlSerialize:
			{
				XmlSerialize *xs = (XmlSerialize *) node;

				if (walker(xs->expr, context))
					return true;
				if (walker(xs->typeName, context))
					return true;
			}
			break;
		case T_WithClause:
			return walker(((WithClause *) node)->ctes, context);
		case T_InferClause:
			{
				InferClause *stmt = (InferClause *) node;

				if (walker(stmt->indexElems, context))
					return true;
				if (walker(stmt->whereClause, context))
					return true;
			}
			break;
		case T_OnConflictClause:
			{
				OnConflictClause *stmt = (OnConflictClause *) node;

				if (walker(stmt->infer, context))
					return true;
				if (walker(stmt->targetList, context))
					return true;
				if (walker(stmt->whereClause, context))
					return true;
			}
			break;
		case T_CommonTableExpr:
			return walker(((CommonTableExpr *) node)->ctequery, context);
		default:

			/*
			 * elog(ERROR, "unrecognized node type: %d", (int) nodeTag(node));
			 */
			break;
	}
	return false;
}

/*
 * Search function name in whilelist or blacklist regex array
 * Return 1 on success (found in list)
 * Return 0 when not found in list
 * Return -1 if the given search type doesn't exist.
 * Search type supported are: WHITELIST and BLACKLIST
 */
int
pattern_compare(char *str, const int type, const char *param_name)
{
	int			i = 0;
	char	   *s;
	int			result = 0;

	RegPattern *lists_patterns;
	int		   *pattc;

	if (strcmp(param_name, "white_function_list") == 0 ||
		strcmp(param_name, "black_function_list") == 0)
	{
		lists_patterns = pool_config->lists_patterns;
		pattc = &pool_config->pattc;

	}
	else if (strcmp(param_name, "white_memqcache_table_list") == 0 ||
			 strcmp(param_name, "black_memqcache_table_list") == 0)
	{
		lists_patterns = pool_config->lists_memqcache_table_patterns;
		pattc = &pool_config->memqcache_table_pattc;

	}
	else if (strcmp(param_name, "black_query_pattern_list") == 0)
	{
		lists_patterns = pool_config->lists_query_patterns;
		pattc = &pool_config->query_pattc;

	}
	else
	{
		ereport(WARNING,
				(errmsg("pattern_compare: unknown paramname %s", param_name)));
		return -1;
	}

	s = strip_quote(str);
	if (!s)
	{
		elog(WARNING, "pattern_compare: strip_quote() returns error");
		return -1;
	}

	for (i = 0; i < *pattc; i++)
	{
		if (lists_patterns[i].type != type)
			continue;

		if (regexec(&lists_patterns[i].regexv, s, 0, 0, 0) == 0)
		{
			switch (type)
			{
					/* return 1 if string matches whitelist pattern */
				case WHITELIST:
					ereport(DEBUG2,
							(errmsg("comparing function name in whitelist regex array"),
							 errdetail("pattern_compare: %s (%s) matched: %s",
									   param_name, lists_patterns[i].pattern, s)));
					result = 1;
					break;
					/* return 1 if string matches blacklist pattern */
				case BLACKLIST:
					ereport(DEBUG2,
							(errmsg("comparing function name in blacklist regex array"),
							 errdetail("pattern_compare: %s (%s) matched: %s",
									   param_name, lists_patterns[i].pattern, s)));
					result = 1;
					break;
				default:
					ereport(WARNING,
							(errmsg("pattern_compare: \"%s\" unknown pattern match type: \"%s\"", param_name, s)));
					result = -1;
					break;
			}
			/* return the result */
			break;
		}
		ereport(DEBUG2,
				(errmsg("comparing function name in blacklist/whitelist regex array"),
				 errdetail("pattern_compare: %s (%s) not matched: %s",
						   param_name, lists_patterns[i].pattern, s)));
	}

	free(s);
	return result;
}

/*
 * Returns double quotes stripped version of malloced string.
 * Callers must free() after using it.
 * Returns NULL on error.
 */
static char *
strip_quote(char *str)
{
	char	   *after;
	int		   len;
	int			i = 0;

	len = strlen(str);
	after = malloc(sizeof(char) * len + 1);
	if (!after)
	{
		return NULL;
	}

	if (len == 0)
	{
		/* empty string case */
		*after = '\0';
		return after;
	}

	do
	{
		if (*str != '"')
		{
			after[i] = *str;
			i++;
		}
		str++;
	} while (*str != '\0');

	after[i] = '\0';

	return after;
}

/*==========================================================================*/
/* READ OR WRITE                                                            */
/*==========================================================================*/
/*
 * From syntactically analysis decide the statement to be sent to the
 * primary, the standby or either or both in master/slave+HR/SR mode.
 */
POOL_DEST send_to_where(Node *node, char *query)
{
/* From storage/lock.h */
#define NoLock					0
#define AccessShareLock			1	/* SELECT */
#define RowShareLock			2	/* SELECT FOR UPDATE/FOR SHARE */
#define RowExclusiveLock		3	/* INSERT, UPDATE, DELETE */
#define ShareUpdateExclusiveLock 4	/* VACUUM (non-FULL),ANALYZE, CREATE INDEX
									 * CONCURRENTLY */
#define ShareLock				5	/* CREATE INDEX (WITHOUT CONCURRENTLY) */
#define ShareRowExclusiveLock	6	/* like EXCLUSIVE MODE, but allows ROW
									 * SHARE */
#define ExclusiveLock			7	/* blocks ROW SHARE/SELECT...FOR UPDATE */
#define AccessExclusiveLock		8	/* ALTER TABLE, DROP TABLE, VACUUM FULL,
									 * and unqualified LOCK TABLE */

/* From 9.5 include/nodes/node.h ("TAGS FOR STATEMENT NODES" part) */
	static NodeTag nodemap[] = {
		T_RawStmt,
		T_Query,
		T_PlannedStmt,
		T_InsertStmt,
		T_DeleteStmt,
		T_UpdateStmt,
		T_SelectStmt,
		T_AlterTableStmt,
		T_AlterTableCmd,
		T_AlterDomainStmt,
		T_SetOperationStmt,
		T_GrantStmt,
		T_GrantRoleStmt,
		T_AlterDefaultPrivilegesStmt,
		T_ClosePortalStmt,
		T_ClusterStmt,
		T_CopyStmt,
		T_CreateStmt,			/* CREATE TABLE */
		T_DefineStmt,			/* CREATE AGGREGATE, OPERATOR, TYPE */
		T_DropStmt,				/* DROP TABLE etc. */
		T_TruncateStmt,
		T_CommentStmt,
		T_FetchStmt,
		T_IndexStmt,			/* CREATE INDEX */
		T_CreateFunctionStmt,
		T_AlterFunctionStmt,
		T_DoStmt,
		T_RenameStmt,			/* ALTER AGGREGATE etc. */
		T_RuleStmt,				/* CREATE RULE */
		T_NotifyStmt,
		T_ListenStmt,
		T_UnlistenStmt,
		T_TransactionStmt,
		T_ViewStmt,				/* CREATE VIEW */
		T_LoadStmt,
		T_CreateDomainStmt,
		T_CreatedbStmt,
		T_DropdbStmt,
		T_VacuumStmt,
		T_ExplainStmt,
		T_CreateTableAsStmt,
		T_CreateSeqStmt,
		T_AlterSeqStmt,
		T_VariableSetStmt,		/* SET */
		T_VariableShowStmt,
		T_DiscardStmt,
		T_CreateTrigStmt,
		T_CreatePLangStmt,
		T_CreateRoleStmt,
		T_AlterRoleStmt,
		T_DropRoleStmt,
		T_LockStmt,
		T_ConstraintsSetStmt,
		T_ReindexStmt,
		T_CheckPointStmt,
		T_CreateSchemaStmt,
		T_AlterDatabaseStmt,
		T_AlterDatabaseSetStmt,
		T_AlterRoleSetStmt,
		T_CreateConversionStmt,
		T_CreateCastStmt,
		T_CreateOpClassStmt,
		T_CreateOpFamilyStmt,
		T_AlterOpFamilyStmt,
		T_PrepareStmt,
		T_ExecuteStmt,
		T_DeallocateStmt,		/* DEALLOCATE */
		T_DeclareCursorStmt,	/* DECLARE */
		T_CreateTableSpaceStmt,
		T_DropTableSpaceStmt,
		T_AlterObjectSchemaStmt,
		T_AlterOwnerStmt,
		T_DropOwnedStmt,
		T_ReassignOwnedStmt,
		T_CompositeTypeStmt,	/* CREATE TYPE */
		T_CreateEnumStmt,
		T_CreateRangeStmt,
		T_AlterEnumStmt,
		T_AlterTSDictionaryStmt,
		T_AlterTSConfigurationStmt,
		T_CreateFdwStmt,
		T_AlterFdwStmt,
		T_CreateForeignServerStmt,
		T_AlterForeignServerStmt,
		T_CreateUserMappingStmt,
		T_AlterUserMappingStmt,
		T_DropUserMappingStmt,
		T_AlterTableSpaceOptionsStmt,
		T_AlterTableMoveAllStmt,
		T_SecLabelStmt,
		T_CreateForeignTableStmt,
		T_ImportForeignSchemaStmt,
		T_CreateExtensionStmt,
		T_AlterExtensionStmt,
		T_AlterExtensionContentsStmt,
		T_CreateEventTrigStmt,
		T_AlterEventTrigStmt,
		T_RefreshMatViewStmt,
		T_ReplicaIdentityStmt,
		T_AlterSystemStmt,
		T_CreatePolicyStmt,
		T_AlterPolicyStmt,
		T_CreateTransformStmt,
		T_CreateAmStmt,
		T_CreatePublicationStmt,
		T_AlterPublicationStmt,
		T_CreateSubscriptionStmt,
		T_DropSubscriptionStmt,
		T_CreateStatsStmt,
		T_AlterCollationStmt,
	};

	if (bsearch(&nodeTag(node), nodemap, sizeof(nodemap) / sizeof(nodemap[0]),
				sizeof(NodeTag), compare) != NULL)
	{
		/*
		 * SELECT INTO SELECT FOR SHARE or UPDATE
		 */
		if (IsA(node, SelectStmt))
		{
			/* SELECT INTO or SELECT FOR SHARE or UPDATE ? */
			if (pool_has_insertinto_or_locking_clause(node))
				return POOL_PRIMARY;

			/* non-SELECT query in WITH clause ? */
			if (((SelectStmt *) node)->withClause)
			{
				List	   *ctes = ((SelectStmt *) node)->withClause->ctes;
				ListCell   *cte_item;

				foreach(cte_item, ctes)
				{
					CommonTableExpr *cte = (CommonTableExpr *) lfirst(cte_item);

					if (!IsA(cte->ctequery, SelectStmt))
						return POOL_PRIMARY;
				}
			}

			return POOL_EITHER;
		}

		/*
		 * COPY
		 */
		else if (IsA(node, CopyStmt))
		{
			if (((CopyStmt *) node)->is_from)
				return POOL_PRIMARY;
			else
			{
				if (((CopyStmt *) node)->query == NULL)
					return POOL_EITHER;
				else
					return (IsA(((CopyStmt *) node)->query, SelectStmt)) ? POOL_EITHER : POOL_PRIMARY;
			}
		}

		/*
		 * LOCK
		 */
		else if (IsA(node, LockStmt))
		{
			return (((LockStmt *) node)->mode >= RowExclusiveLock) ? POOL_PRIMARY : POOL_BOTH;
		}

		/*
		 * Transaction commands
		 */
		else if (IsA(node, TransactionStmt))
		{
			/*
			 * Check "BEGIN READ WRITE" "START TRANSACTION READ WRITE"
			 */
			if (is_start_transaction_query(node))
			{
				/*
				 * But actually, we send BEGIN to standby if it's BEGIN READ
				 * WRITE or START TRANSACTION READ WRITE
				 */
				if (is_read_write((TransactionStmt *) node))
					return POOL_BOTH;

				/*
				 * Other TRANSACTION start commands are sent to both primary
				 * and standby
				 */
				else
					return POOL_BOTH;
			}
			/* SAVEPOINT related commands are sent to both primary and standby */
			else if (is_savepoint_query(node))
				return POOL_BOTH;

			/*
			 * 2PC commands
			 */
			else if (is_2pc_transaction_query(node))
				return POOL_PRIMARY;
			else
				/* COMMIT etc. */
				return POOL_BOTH;
		}

		/*
		 * SET
		 */
		else if (IsA(node, VariableSetStmt))
		{
			ListCell   *list_item;
			bool		ret = POOL_BOTH;

			/*
			 * SET transaction_read_only TO off
			 */
			if (((VariableSetStmt *) node)->kind == VAR_SET_VALUE &&
				!strcmp(((VariableSetStmt *) node)->name, "transaction_read_only"))
			{
				List	   *options = ((VariableSetStmt *) node)->args;

				foreach(list_item, options)
				{
					A_Const    *v = (A_Const *) lfirst(list_item);

					switch (v->val.type)
					{
						case T_String:
							if (!strcasecmp(v->val.val.str, "off") ||
								!strcasecmp(v->val.val.str, "f") ||
								!strcasecmp(v->val.val.str, "false"))
								ret = POOL_PRIMARY;
							break;
						case T_Integer:
							if (v->val.val.ival)
								ret = POOL_PRIMARY;
						default:
							break;
					}
				}
				return ret;
			}

			/*
			 * SET TRANSACTION ISOLATION LEVEL SERIALIZABLE or SET SESSION
			 * CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE or
			 * SET transaction_isolation TO 'serializable' SET
			 * default_transaction_isolation TO 'serializable'
			 */
			else if (is_set_transaction_serializable(node))
			{
				return POOL_PRIMARY;
			}

			/*
			 * Check "SET TRANSACTION READ WRITE" "SET SESSION CHARACTERISTICS
			 * AS TRANSACTION READ WRITE"
			 */
			else if (((VariableSetStmt *) node)->kind == VAR_SET_MULTI &&
					 (!strcmp(((VariableSetStmt *) node)->name, "TRANSACTION") ||
					  !strcmp(((VariableSetStmt *) node)->name, "SESSION CHARACTERISTICS")))
			{
				List	   *options = ((VariableSetStmt *) node)->args;

				foreach(list_item, options)
				{
					DefElem    *opt = (DefElem *) lfirst(list_item);

					if (!strcmp("transaction_read_only", opt->defname))
					{
						bool		read_only;

						read_only = ((A_Const *) opt->arg)->val.val.ival;
						if (!read_only)
							return POOL_PRIMARY;
					}
				}
				return POOL_BOTH;
			}
			else
			{
				/*
				 * All other SET command sent to both primary and standby
				 */
				return POOL_BOTH;
			}
		}

		/*
		 * DISCARD
		 */
		else if (IsA(node, DiscardStmt))
		{
			return POOL_BOTH;
		}

		/*
		 * PREPARE
		 */
		else if (IsA(node, PrepareStmt))
		{
			PrepareStmt *prepare_statement = (PrepareStmt *) node;

			char	   *string = nodeToString(prepare_statement->query);

			/* Note that this is a recursive call */
			return send_to_where((Node *) (prepare_statement->query), string);
		}

		/*
		 * EXECUTE
		 */
		else if (IsA(node, ExecuteStmt))
		{
			/*
			 * This is temporary decision. where_to_send will inherit same
			 * destination AS PREPARE.
			 */
			return POOL_PRIMARY;
		}

		/*
		 * DEALLOCATE
		 */
		else if (IsA(node, DeallocateStmt))
		{
			/*
			 * This is temporary decision. where_to_send will inherit same
			 * destination AS PREPARE.
			 */
			return POOL_PRIMARY;
		}

		/*
		 * SHOW
		 */
		else if (IsA(node, VariableShowStmt))
		{
			return POOL_EITHER;
		}

		/*
		 * Other statements are sent to primary
		 */
		return POOL_PRIMARY;
	}

	/*
	 * All unknown statements are sent to primary
	 */
	return POOL_PRIMARY;
}

/*
 * Return true if this SELECT h
 */
void is_read_or_write_query(Node *node, char *query)
{
	POOL_DEST   dest;

	dest = send_to_where(node, query);

	if (dest == POOL_PRIMARY)
		printf("query: \"%s\" is a WRITE query\n", query);
	else if (dest == POOL_EITHER)
		printf("query: \"%s\" is a READ query\n", query);
	else if (dest == POOL_BOTH)
		printf("query: \"%s\" to primary node and load blance node\n", query);
}

/*
 * Return true if this SELECT has INSERT INTO or FOR SHARE or FOR UPDATE.
 */
bool
pool_has_insertinto_or_locking_clause(Node *node)
{
	SelectContext ctx;

	if (!IsA(node, SelectStmt))
		return false;

	ctx.has_insertinto_or_locking_clause = false;

	raw_expression_tree_walker(node, insertinto_or_locking_clause_walker, &ctx);

	ereport(DEBUG1,
			(errmsg("checking if query has INSERT INTO, FOR SHARE or FOR UPDATE"),
			 errdetail("result = %d", ctx.has_insertinto_or_locking_clause)));

	return ctx.has_insertinto_or_locking_clause;
}

/*
 * Walker function to find intoClause or lockingClause.
 */
static bool
insertinto_or_locking_clause_walker(Node *node, void *context)
{
	SelectContext *ctx = (SelectContext *) context;

	if (node == NULL)
		return false;

	if (IsA(node, IntoClause) ||IsA(node, LockingClause))
	{
		ctx->has_insertinto_or_locking_clause = true;
		return false;
	}
	return raw_expression_tree_walker(node, insertinto_or_locking_clause_walker, ctx);
}

/* compare function for bsearch() */
int
compare(const void *p1, const void *p2)
{
	int			v1,
				v2;

	v1 = *(NodeTag *) p1;
	v2 = *(NodeTag *) p2;
	return (v1 > v2) ? 1 : ((v1 == v2) ? 0 : -1);
}

/*
 * Return true if the query is SAVEPOINT related query.
 */
bool
is_savepoint_query(Node *node)
{
	if (((TransactionStmt *) node)->kind == TRANS_STMT_SAVEPOINT ||
		((TransactionStmt *) node)->kind == TRANS_STMT_ROLLBACK_TO ||
		((TransactionStmt *) node)->kind == TRANS_STMT_RELEASE)
		return true;

	return false;
}

/*
 * Returns true if SQL is transaction starting command (START
 * TRANSACTION or BEGIN)
 */
bool
is_start_transaction_query(Node *node)
{
	TransactionStmt *stmt;

	if (node == NULL || !IsA(node, TransactionStmt))
		return false;

	stmt = (TransactionStmt *) node;
	return stmt->kind == TRANS_STMT_START || stmt->kind == TRANS_STMT_BEGIN;
}

/*
 * Return true if the query is 2PC transaction query.
 */
bool
is_2pc_transaction_query(Node *node)
{
	if (((TransactionStmt *) node)->kind == TRANS_STMT_PREPARE ||
		((TransactionStmt *) node)->kind == TRANS_STMT_COMMIT_PREPARED ||
		((TransactionStmt *) node)->kind == TRANS_STMT_ROLLBACK_PREPARED)
		return true;

	return false;
}

/*
 * Return true if start transaction query with "READ WRITE" option.
 */
bool
is_read_write(TransactionStmt *node)
{
	ListCell   *list_item;

	List	   *options = node->options;

	foreach(list_item, options)
	{
		DefElem    *opt = (DefElem *) lfirst(list_item);

		if (!strcmp("transaction_read_only", opt->defname))
		{
			bool		read_only;

			read_only = ((A_Const *) opt->arg)->val.val.ival;
			if (read_only)
				return false;	/* TRANSACTION READ ONLY */
			else

				/*
				 * TRANSACTION READ WRITE specified. This sounds a little bit
				 * strange, but actually the parse code works in the way.
				 */
				return true;
		}
	}

	/*
	 * No TRANSACTION READ ONLY/READ WRITE clause specified.
	 */
	return false;
}

/*
 * Returns true if the query is one of:
 *
 * SET TRANSACTION ISOLATION LEVEL SERIALIZABLE or
 * SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE or
 * SET transaction_isolation TO 'serializable'
 * SET default_transaction_isolation TO 'serializable'
 */
bool
is_set_transaction_serializable(Node *node)
{
	ListCell   *list_item;

	if (!IsA(node, VariableSetStmt))
		return false;

	if (((VariableSetStmt *) node)->kind == VAR_SET_VALUE &&
		(!strcmp(((VariableSetStmt *) node)->name, "transaction_isolation") ||
		 !strcmp(((VariableSetStmt *) node)->name, "default_transaction_isolation")))
	{
		List	   *options = ((VariableSetStmt *) node)->args;

		foreach(list_item, options)
		{
			A_Const    *v = (A_Const *) lfirst(list_item);

			switch (v->val.type)
			{
				case T_String:
					if (!strcasecmp(v->val.val.str, "serializable"))
						return true;
					break;
				default:
					break;
			}
		}
		return false;
	}

	else if (((VariableSetStmt *) node)->kind == VAR_SET_MULTI &&
			 (!strcmp(((VariableSetStmt *) node)->name, "TRANSACTION") ||
			  !strcmp(((VariableSetStmt *) node)->name, "SESSION CHARACTERISTICS")))
	{
		List	   *options = ((VariableSetStmt *) node)->args;

		foreach(list_item, options)
		{
			DefElem    *opt = (DefElem *) lfirst(list_item);

			if (!strcmp("transaction_isolation", opt->defname) ||
				!strcmp("default_transaction_isolation", opt->defname))
			{
				A_Const    *v = (A_Const *) opt->arg;

				if (!strcasecmp(v->val.val.str, "serializable"))
					return true;
			}
		}
	}
	return false;
}

void
ExceptionalCondition(const char *conditionName,
                     const char *errorType,
                     const char *fileName,
                     int lineNumber)
{
    if (!PointerIsValid(conditionName)
        || !PointerIsValid(fileName)
        || !PointerIsValid(errorType))
        write_stderr("TRAP: ExceptionalCondition: bad arguments\n");
    else
    {   
        write_stderr("TRAP: %s(\"%s\", File: \"%s\", Line: %d)\n",
                     errorType, conditionName,
                     fileName, lineNumber);
    }   

    /* Usually this shouldn't be needed, but make sure the msg went out */
    fflush(stderr);

#ifdef SLEEP_ON_ASSERT

    /*  
     * It would be nice to use pg_usleep() here, but only does 2000 sec or 33
     * minutes, which seems too short.
     */
    sleep(1000000);
#endif

    abort();                                                                             
}

void
free_select_result(POOL_SELECT_RESULT * result)
{                                                                      
}

bool
pool_has_to_regclass(void)
{
    return false;
}

char *
remove_quotes_and_schema_from_relname(char *table)
{
    return table;
}

int
pool_get_major_version(void)
{
    return PROTO_MAJOR_V3;
}

POOL_RELCACHE *
pool_create_relcache(int cachesize, char *sql, func_ptr register_func, func_ptr unregister_func, bool issessionlocal)
{
    return (POOL_RELCACHE *) 1;
}

int
pool_virtual_master_db_node_id(void)
{
        return 0;
}

bool
pool_has_pgpool_regclass(void)
{
        return false;
}

POOL_SESSION_CONTEXT *
pool_get_session_context(bool noerror)
{
	return NULL;
}

int
pool_frontend_exists(void)
{
	return 0;
}

int
get_frontend_protocol_version(void)
{
	return 0;
}

int
set_pg_frontend_blocking(bool blocking)
{
	return 0;
}

int
pool_send_to_frontend(char *data, int len, bool flush)
{
	return 0;
}
